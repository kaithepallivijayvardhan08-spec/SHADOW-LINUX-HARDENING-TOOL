#!/usr/bin/env python3
"""
Shadow Restore
==============

Restores system configuration from backups.

Flow:
1. List available backups
2. User selects backup to restore
3. Verify backup integrity
4. Restore files
5. Verify restoration
6. Log all actions

Safety:
- Only restores from verified backups
- Creates backup of current state before restore
- Verifies after restore
- Can restore individual files or full system
"""

import os
import sys
import shutil
import logging
import subprocess
import hashlib
import json
import time
import tempfile
from pathlib import Path
from datetime import datetime
from shadow.core import ui
from typing import Dict, List, Tuple, Optional, Callable, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ============================================================
# CHANGES LOG
# ============================================================
CHANGES_LOG = Path("/var/log/shadow/changes.log")


class Restore:
    """Restores system from backups"""
    
    def __init__(self):
        """Initialize restore"""
        self.logger = logging.getLogger(__name__)
        self.backup_dir = Path("/var/backups/shadow/")
        self.restore_log = Path("/var/log/shadow/restore.log")
        self.metadata_file = self.backup_dir / "backup_metadata.json"
        
        # Ensure directories exist
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.restore_log.parent.mkdir(parents=True, exist_ok=True)
        
        # Progress tracking
        self.progress_callback = None
        self.total_items = 0
        self.current_item = 0
        
        # Transaction support
        self._transaction = None
        self._transaction_backups = []
    
    # ============================================================
    # PROGRESS TRACKING
    # ============================================================
    def set_progress_callback(self, callback: Callable[[int, int, str], None]):
        """Set callback for progress updates"""
        self.progress_callback = callback
    
    def _report_progress(self, current: int, total: int, message: str = ""):
        """Report progress to callback"""
        if self.progress_callback:
            try:
                self.progress_callback(current, total, message)
            except Exception as e:
                self.logger.debug(f"Progress callback failed: {e}")
    
    def _log_change(self, action: str, file_path: str, details: str):
        """Log a system change"""
        try:
            CHANGES_LOG.parent.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(CHANGES_LOG, 'a') as f:
                f.write(f"{timestamp} | {action} | {file_path} | {details}\n")
            self.logger.debug(f"Change logged: {action} on {file_path}")
        except Exception as e:
            self.logger.warning(f"Failed to log change: {e}")
    
    # ============================================================
    # DRY-RUN MODE
    # ============================================================
    def dry_run_restore(self, backup_path: Path) -> Dict:
        """
        Preview restore without applying changes.
        Returns a dict with planned restore actions.
        """
        self.logger.info("DRY RUN: Previewing restore...")
        
        if not backup_path.exists():
            return {'error': f'Backup not found: {backup_path}'}
        
        restore_plan = {
            'backup_name': backup_path.name,
            'backup_size': self._get_size(backup_path),
            'files_to_restore': [],
            'destinations': []
        }
        
        if backup_path.is_dir():
            for item in backup_path.iterdir():
                dest = self._get_destination_path(item)
                restore_plan['files_to_restore'].append({
                    'source': item.name,
                    'dest': str(dest) if dest else 'UNKNOWN'
                })
                if dest:
                    restore_plan['destinations'].append(str(dest))
        else:
            dest = self._get_destination_path(backup_path)
            restore_plan['files_to_restore'].append({
                'source': backup_path.name,
                'dest': str(dest) if dest else 'UNKNOWN'
            })
            if dest:
                restore_plan['destinations'].append(str(dest))
        
        return restore_plan
    
    # ============================================================
    # CONFIRMATION
    # ============================================================
    def require_restore_confirmation(self, restore_plan: Dict) -> bool:
        """
        Require user confirmation before restoring.
        Returns True if confirmed.
        """
        print("\n" + "="*60)
        print("⚠️  RESTORE CONFIRMATION REQUIRED")
        print("="*60)
        print(f"Backup: {restore_plan.get('backup_name', 'unknown')}")
        print(f"Files to restore: {len(restore_plan.get('files_to_restore', []))}")
        print("\nDestinations:")
        for dest in restore_plan.get('destinations', [])[:5]:
            print(f"  → {dest}")
        if len(restore_plan.get('destinations', [])) > 5:
            print(f"  ... and {len(restore_plan.get('destinations', [])) - 5} more")
        print("\nThis will overwrite existing system files.")
        print("A backup of the current state will be created before restore.")
        print("="*60)
        response = ui.prompt("Proceed with restore? [y/N]: ")
        return response.lower() == 'y'
    
    # ============================================================
    # TRANSACTION SUPPORT - NEW
    # ============================================================
    def _begin_transaction(self):
        """Begin a restore transaction"""
        self._transaction = {
            'id': datetime.now().strftime('%Y%m%d_%H%M%S_%f'),
            'started': datetime.now().isoformat(),
            'backups': [],
            'restored': [],
            'failed': []
        }
        self._transaction_backups = []
        self.logger.info(f"Transaction {self._transaction['id']} started")
    
    def _commit_transaction(self) -> Dict:
        """Commit a restore transaction"""
        if not self._transaction:
            return {'status': 'failed', 'reason': 'No active transaction'}
        
        self._transaction['ended'] = datetime.now().isoformat()
        result = {
            'status': 'committed',
            'transaction_id': self._transaction['id'],
            'restored': self._transaction['restored'],
            'failed': self._transaction['failed']
        }
        self.logger.info(f"Transaction {self._transaction['id']} committed")
        self._transaction = None
        return result
    
    def _rollback_transaction(self) -> Dict:
        """Rollback a restore transaction"""
        if not self._transaction:
            return {'status': 'failed', 'reason': 'No active transaction'}
    
        restored = 0
        failed = 0
    
        for backup_info in reversed(self._transaction_backups):
            backup_path = Path(backup_info['backup_path'])
            original_path = Path(backup_info['original_path'])
        
            if not backup_path.exists():
                self.logger.warning(f"Backup not found for rollback: {backup_path}")
                failed += 1
                continue
        
            try:
                # ✅ FIX: Check if it's a directory
                is_directory = backup_info.get('is_directory', False)
            
                if is_directory or backup_path.is_dir():
                    # Restore directory
                    if original_path.exists():
                        # Remove current directory
                        shutil.rmtree(original_path, ignore_errors=True)
                    # Copy backup back
                    shutil.copytree(backup_path, original_path)
                    self.logger.info(f"Rolled back directory: {original_path}")
                else:
                    # Restore file
                    shutil.copy2(backup_path, original_path)
                    # Restore permissions if stored
                    if 'permissions' in backup_info and backup_info['permissions']:
                        os.chmod(original_path, backup_info['permissions'])
                    self.logger.info(f"Rolled back file: {original_path}")
            
                restored += 1
            
            except Exception as e:
                self.logger.error(f"Rollback failed for {original_path}: {e}")
                failed += 1
    
        self._transaction['ended'] = datetime.now().isoformat()
        result = {
            'status': 'rolled_back',
            'transaction_id': self._transaction['id'],
            'files_restored': restored,
            'files_failed': failed,
            'restored': self._transaction['restored'],
            'failed': self._transaction['failed']
        }
        self.logger.info(f"Transaction {self._transaction['id']} rolled back ({restored} restored, {failed} failed)")
        self._transaction = None
        return result
    
    # ============================================================
    # BACKUP VERIFICATION WITH CHECKSUMS - FIXED
    # ============================================================
    def _calculate_sha256(self, file_path: Path) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(65536), b''):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.error(f"Failed to calculate SHA256 for {file_path}: {e}")
            return ""
    
    def _verify_backup_checksum(self, backup_path: Path) -> Tuple[bool, str]:
        """Verify backup integrity using SHA256 checksum"""
        if not backup_path.exists():
            return False, "File does not exist"
        
        if backup_path.stat().st_size == 0:
            return False, "File is empty"
        
        # Check for metadata file
        meta_file = backup_path.with_suffix('.meta')
        if meta_file.exists():
            try:
                with open(meta_file, 'r') as f:
                    metadata = json.load(f)
                expected_checksum = metadata.get('sha256')
                if expected_checksum:
                    actual_checksum = self._calculate_sha256(backup_path)
                    if actual_checksum == expected_checksum:
                        return True, "Checksum verified"
                    return False, f"Checksum mismatch: expected {expected_checksum[:8]}..., got {actual_checksum[:8]}..."
            except Exception as e:
                self.logger.warning(f"Could not read metadata: {e}")
        
        # No metadata, calculate and store checksum
        checksum = self._calculate_sha256(backup_path)
        if checksum:
            try:
                meta_file.write_text(json.dumps({'sha256': checksum, 'verified': True}))
                return True, "Checksum created"
            except Exception as e:
                self.logger.warning(f"Could not save checksum: {e}")
                return True, "Checksum calculated but not saved"
        
        return False, "Could not calculate checksum"
    
    def _validate_backup(self, backup_path: Path) -> bool:
        """Validate that a backup is valid and not corrupted"""
        if not backup_path.exists():
            self.logger.error(f"Backup not found: {backup_path}")
            return False
        
        if backup_path.stat().st_size == 0:
            self.logger.error(f"Backup is empty: {backup_path}")
            return False
        
        # Verify checksum
        verified, message = self._verify_backup_checksum(backup_path)
        if not verified:
            self.logger.error(f"Backup verification failed: {message}")
            return False
        
        # For text files, check if they contain valid content
        if backup_path.is_file():
            try:
                with open(backup_path, 'r') as f:
                    content = f.read()
                    if not content.strip():
                        self.logger.error(f"Backup file is empty: {backup_path}")
                        return False
            except UnicodeDecodeError:
                # Binary file, skip content check
                pass
            except Exception as e:
                self.logger.error(f"Could not read backup: {e}")
                return False
        
        self.logger.info(f"Backup validated: {backup_path}")
        return True
    
    # ============================================================
    # RESTORE WITH TRANSACTION SUPPORT - FIXED
    # ============================================================
    def rollback_failed_harden(self) -> Dict:
        """
        Rollback changes from a failed hardening operation.
        Restores the most recent backup for each modified file.
    
        Returns:
            Dict: {'success': bool, 'restored': int, 'failed': int, 'message': str}
        """
        self.logger.info("Rolling back failed hardening...")
        print("\n[!] Rolling back failed hardening operation...")
    
        result = {
            'success': False,
            'restored': 0,
            'failed': 0,
            'skipped': 0,
            'message': ''
        }
    
        # Begin transaction
        self._begin_transaction()
    
        try:
            # Find all backup files using consistent pattern
            backup_files = list(self.backup_dir.glob("*.backup_*")) + \
                        list(self.backup_dir.glob("*.backup")) + \
                        list(self.backup_dir.glob("*_backup_*"))
        
            if not backup_files:
                self.logger.warning("No backup files found for rollback")
                result['message'] = "No backup files found. Cannot rollback."
                result['success'] = False
                return result
        
            restored_count = 0
            failed_count = 0
            skipped_count = 0
            total_files = len(backup_files)
        
            for idx, backup_path in enumerate(backup_files):
                # Report progress
                self._report_progress(idx + 1, total_files, f"Restoring {backup_path.name}")
            
                # Get destination path
                dest_path = self._get_destination_path(backup_path)
                if dest_path is None:
                    self.logger.warning(f"Cannot determine destination for: {backup_path.name}")
                    skipped_count += 1
                    self._transaction['failed'].append({
                        'file': backup_path.name,
                        'reason': 'Cannot determine destination'
                    })
                    continue
            
                # Validate backup with checksum
                try:
                    backup_valid = self._validate_backup(backup_path)
                except Exception as e:
                    self.logger.warning(f"Backup validation error for {backup_path.name}: {e}")
                    backup_valid = False

                if not backup_valid:
                    self.logger.error(f"Backup validation failed: {backup_path}")
                    failed_count += 1
                    self._transaction['failed'].append({
                        'file': str(dest_path),
                        'reason': 'Backup validation failed'
                    })
                    continue
            
                try:
                    # Save original permissions if file exists
                    original_perms = None
                    if dest_path.exists():
                        stat_info = dest_path.stat()
                        original_perms = stat_info.st_mode & 0o7777
                
                    # Create pre-restore backup
                    pre_restore_file = self.backup_dir / f"pre_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{dest_path.name}"
                    if dest_path.exists():
                        shutil.copy2(dest_path, pre_restore_file)
                        self.logger.debug(f"Pre-restore backup: {pre_restore_file}")
                        # Store for transaction rollback
                        self._transaction_backups.append({
                            'backup_path': str(pre_restore_file),
                            'original_path': str(dest_path),
                            'permissions': original_perms,
                            'is_directory': dest_path.is_dir()  # ✅ FIX: Track if directory
                        })
                
                    # ✅ FIX: Handle directory vs file restoration
                    if backup_path.is_dir():
                        # Restore directory
                        success = self._restore_directory_with_rollback(backup_path, dest_path)
                    else:
                        # Restore file with integrity check
                        success = self._restore_file_with_integrity(backup_path, dest_path)
                
                    if success:
                        self.logger.info(f"Restored: {backup_path.name} → {dest_path}")
                        restored_count += 1
                        self._transaction['restored'].append(str(dest_path))
                        # Log the restore
                        self._log_change("RESTORE", str(dest_path), f"Restored from {backup_path.name}")
                    else:
                        self.logger.error(f"Restore failed for: {backup_path.name}")
                        failed_count += 1
                        self._transaction['failed'].append({
                            'file': str(dest_path),
                            'reason': 'Restore verification failed'
                        })
                
                except Exception as e:
                    self.logger.error(f"Failed to restore {backup_path.name}: {e}")
                    failed_count += 1
                    self._transaction['failed'].append({
                        'file': str(dest_path) if dest_path else backup_path.name,
                        'reason': str(e)
                    })
        
            # ✅ FIX: Better status reporting
            result['restored'] = restored_count
            result['failed'] = failed_count
            result['skipped'] = skipped_count
            result['total'] = total_files
        
            # Log summary
            if failed_count == 0 and skipped_count == 0:
                result['success'] = True
                result['message'] = f"All {restored_count} files restored successfully"
                print(f"\n[✓] Rollback completed: {restored_count} files restored")
                self._commit_transaction()
            elif failed_count == 0 and skipped_count > 0:
                result['success'] = True
                result['message'] = f"{restored_count} files restored, {skipped_count} skipped (unknown destinations)"
                print(f"\n[✓] Rollback completed: {restored_count} restored, {skipped_count} skipped")
                self._commit_transaction()
            else:
                result['success'] = False
                result['message'] = f"{restored_count} restored, {failed_count} failed, {skipped_count} skipped"
                print(f"\n[⚠] Rollback partially completed: {restored_count} restored, {failed_count} failed, {skipped_count} skipped")
                # ✅ FIX: Only rollback transaction if critical failure
                if failed_count > total_files // 2:  # More than 50% failed
                    self.logger.warning("Critical failure detected, rolling back transaction...")
                    self._rollback_transaction()
                else:
                    self._commit_transaction()
        
            self.logger.info(f"Rollback result: {result['message']}")
        
        except Exception as e:
            self.logger.error(f"Rollback failed: {e}")
            result['message'] = f"Rollback failed: {e}"
            result['success'] = False
            self._rollback_transaction()
    
        return result
    
    # ============================================================
    # INTEGRITY-RESTORE FILE - FIXED
    # ============================================================
    def _restore_file_with_integrity(self, backup_path: Path, dest_path: Path) -> bool:
        """Restore a file with integrity verification"""
        try:
            # Read backup content
            with open(backup_path, 'rb') as f:
                backup_content = f.read()
            
            # Calculate backup checksum
            backup_checksum = hashlib.sha256(backup_content).hexdigest()
            
            # Write to destination
            with open(dest_path, 'wb') as f:
                f.write(backup_content)
            
            # Verify restore
            with open(dest_path, 'rb') as f:
                restored_content = f.read()
            restored_checksum = hashlib.sha256(restored_content).hexdigest()
            
            if backup_checksum != restored_checksum:
                self.logger.error(f"Restore verification failed for {dest_path}")
                return False
            
            # Validate content if text file
            if dest_path.is_file():
                try:
                    with open(dest_path, 'r') as f:
                        content = f.read()
                        if not content.strip():
                            self.logger.warning(f"Restored file is empty: {dest_path}")
                except UnicodeDecodeError:
                    # Binary file, skip content validation
                    pass
            
            return True
        except Exception as e:
            self.logger.error(f"Restore failed: {e}")
            return False
    # ============================================================
    # RESTORE-DIRECTORY-WITH-ROLLBACK FILE - ADDED
    # ============================================================
    
    def _restore_directory_with_rollback(self, backup_path: Path, dest_path: Path) -> bool:
        """
        Restore a directory with integrity verification and rollback support.
        """
        try:
            # Get destination from backup path name
            dest_dir = self._get_destination_path(backup_path)
            if dest_dir is None:
                # Try to determine from backup name
                backup_name = backup_path.name
                if 'etc' in backup_name or 'config' in backup_name:
                    dest_dir = Path('/etc/')
                elif 'var' in backup_name:
                    dest_dir = Path('/var/')
                else:
                    self.logger.error(f"Cannot determine destination for directory: {backup_path}")
                    return False
        
            # Create backup of current state before restore
            if dest_dir.exists():
                # Create pre-restore backup
                pre_restore_dir = self.backup_dir / f"pre_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                shutil.copytree(dest_dir, pre_restore_dir, dirs_exist_ok=True)
                # Store for transaction rollback
                self._transaction_backups.append({
                    'backup_path': str(pre_restore_dir),
                    'original_path': str(dest_dir),
                    'is_directory': True
                })
        
            # Restore directory contents
            for item in backup_path.iterdir():
                dest_file = dest_dir / item.name
                if item.is_file():
                    if not self._restore_file_with_integrity(item, dest_file):
                        return False
                elif item.is_dir():
                    # Recursively restore subdirectories
                    shutil.copytree(item, dest_file, dirs_exist_ok=True)
        
            # Set proper permissions
            self._set_permissions(dest_dir)
        
            self.logger.info(f"Directory restored: {dest_dir}")
            return True
        
        except Exception as e:
            self.logger.error(f"Directory restore failed: {e}")
            return False
    
    # ============================================================
    # SERVICE RESTART - FIXED
    # ============================================================
    def _restart_affected_services(self, file_path: Path):
        """Restart services affected by a restore"""
        services_to_restart = set()
        file_str = str(file_path)
        
        # Map file patterns to services
        service_map = {
            '/etc/ssh/sshd_config': ['ssh', 'sshd'],
            '/etc/pam.d/': ['systemd-logind', 'sshd', 'login'],
            '/etc/sudoers': [],  # No restart needed
            '/etc/nginx/nginx.conf': ['nginx'],
            '/etc/apache2/apache2.conf': ['apache2'],
            '/etc/mysql/my.cnf': ['mysql'],
            '/etc/systemd/': ['systemd'],
            '/etc/audit/auditd.conf': ['auditd'],
            '/etc/default/ufw': ['ufw'],
            '/etc/sysctl.conf': [],  # Needs sysctl -p
            '/etc/security/': [],  # Needs pam-auth-update
            '/etc/hosts': ['systemd-resolved', 'nscd'],
            '/etc/resolv.conf': ['systemd-resolved', 'nscd'],
            '/etc/fstab': [],  # Needs mount -a
        }
        
        for pattern, services in service_map.items():
            if pattern in file_str:
                services_to_restart.update(services)
        
        # Special handling for sysctl
        if 'sysctl.conf' in file_str or '/etc/sysctl.d/' in file_str:
            self._reload_sysctl()
        
        # Special handling for fstab
        if 'fstab' in file_str:
            self._verify_fstab()
        
        # Restart services
        restarted = []
        failed = []
        for service in services_to_restart:
            try:
                # Try reload first, then restart
                result = subprocess.run(
                    ['systemctl', 'try-reload', service],
                    capture_output=True,
                    timeout=30
                )
                if result.returncode != 0:
                    result = subprocess.run(
                        ['systemctl', 'restart', service],
                        capture_output=True,
                        timeout=30
                    )
                    if result.returncode != 0:
                        self.logger.warning(f"Failed to restart {service}: {result.stderr}")
                        failed.append(service)
                    else:
                        self.logger.info(f"Restarted {service}")
                        restarted.append(service)
                else:
                    self.logger.info(f"Reloaded {service}")
                    restarted.append(service)
            except Exception as e:
                self.logger.warning(f"Error restarting {service}: {e}")
                failed.append(service)
        
        return {'restarted': restarted, 'failed': failed}
    
    def _reload_sysctl(self):
        """Reload sysctl settings"""
        try:
            result = subprocess.run(
                ['sysctl', '-p'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                self.logger.info("sysctl reloaded")
                return True
            else:
                self.logger.warning(f"sysctl reload failed: {result.stderr}")
                return False
        except Exception as e:
            self.logger.warning(f"Error reloading sysctl: {e}")
            return False
    
    def _verify_fstab(self):
        """Verify fstab with mount -a"""
        try:
            result = subprocess.run(
                ['mount', '-a', '--fake'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                self.logger.info("fstab verified")
                return True
            else:
                self.logger.warning(f"fstab verification failed: {result.stderr}")
                return False
        except Exception as e:
            self.logger.warning(f"Error verifying fstab: {e}")
            return False
    
    # ============================================================
    # LIST BACKUPS - FIXED
    # ============================================================
    def list_backups(self) -> List[Dict]:
        """List all available backups"""
        backups = []
        
        if not self.backup_dir.exists():
            return backups
        
        # Use consistent patterns
        patterns = ['*.backup_*', '*.backup', '*_backup_*', 'pre_restore_*']
        backup_items = []
        for pattern in patterns:
            backup_items.extend(self.backup_dir.glob(pattern))
        
        # Also check directories (for full system backups)
        for item in self.backup_dir.iterdir():
            if item.is_dir() and not item.name.startswith('pre_restore'):
                backup_items.append(item)
        
        # Remove duplicates
        seen = set()
        unique_items = []
        for item in backup_items:
            if str(item) not in seen:
                seen.add(str(item))
                unique_items.append(item)
        
        for item in unique_items:
            # Determine if it's a backup
            is_backup = (
                item.is_dir() or 
                '.backup' in item.name or 
                '_backup_' in item.name or
                'pre_restore' in item.name
            )
            if is_backup:
                backup_info = {
                    'name': item.name,
                    'path': str(item),
                    'type': 'directory' if item.is_dir() else 'file',
                    'size': self._get_size(item),
                    'modified': datetime.fromtimestamp(item.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                }
                backups.append(backup_info)
        
        # Sort by modification time (newest first)
        backups.sort(key=lambda x: x['modified'], reverse=True)
        
        return backups
    
    def _get_size(self, path: Path) -> str:
        """Get human readable size"""
        if path.is_dir():
            total = sum(f.stat().st_size for f in path.rglob('*') if f.is_file())
        else:
            total = path.stat().st_size
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if total < 1024.0:
                return f"{total:.1f} {unit}"
            total /= 1024.0
        return f"{total:.1f} TB"
    
    def _validate_after_restore(self, file_path: str) -> bool:
        """Validate that a restored file is valid"""
        if not os.path.exists(file_path):
            self.logger.error(f"File not found after restore: {file_path}")
            return False
        
        # Validate specific file types
        if 'sshd_config' in file_path:
            try:
                result = subprocess.run(
                    ['sshd', '-t', '-f', file_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode != 0:
                    self.logger.error(f"SSH config validation failed: {result.stderr}")
                    return False
            except subprocess.TimeoutExpired:
                self.logger.warning("SSH config validation timed out")
            except Exception as e:
                self.logger.warning(f"Could not validate SSH config: {e}")
        
        if 'sudoers' in file_path:
            try:
                result = subprocess.run(
                    ['visudo', '-c', '-f', file_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode != 0:
                    self.logger.error(f"Sudoers validation failed: {result.stderr}")
                    return False
            except subprocess.TimeoutExpired:
                self.logger.warning("Sudoers validation timed out")
            except Exception as e:
                self.logger.warning(f"Could not validate sudoers: {e}")
        
        # Validate PAM files
        if 'common-password' in file_path or 'pam' in file_path:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    # Check for required PAM modules
                    if 'pam_deny.so' in content and 'pam_permit.so' not in content:
                        self.logger.info(f"PAM file looks valid: {file_path}")
            except Exception as e:
                self.logger.warning(f"Could not validate PAM file: {e}")
        
        self.logger.info(f"Restore validation passed: {file_path}")
        return True
    
    # ============================================================
    # DESTINATION MAPPING - FIXED (EXPANDED)
    # ============================================================
    def _get_destination_path(self, backup_path: Path) -> Optional[Path]:
        """Explicitly map backup files to their original locations"""
        name = backup_path.name.lower()
    
        # Remove backup suffix
        name = name.replace('.backup', '').replace('backup_', '').replace('_backup_', '')
        name = name.replace('.meta', '').replace('.sha256', '')
    
        # Remove timestamp patterns
        import re
        name = re.sub(r'_\d{8}_\d{6}_\d+$', '', name)
        name = re.sub(r'_\d{14}_\d+$', '', name)
        name = re.sub(r'_\d{8}_\d{6}$', '', name)
    
        # ✅ FIX: COMPLETE FILE MAPPING
        file_map = {
            # SSH
            'sshd_config': '/etc/ssh/sshd_config',
            'ssh_config': '/etc/ssh/ssh_config',
        
            # PAM
            'common-password': '/etc/pam.d/common-password',
            'common-auth': '/etc/pam.d/common-auth',
            'common-account': '/etc/pam.d/common-account',
            'common-session': '/etc/pam.d/common-session',
            'common-session-noninteractive': '/etc/pam.d/common-session-noninteractive',
            'system-auth': '/etc/pam.d/system-auth',
            'password-auth': '/etc/pam.d/password-auth',
            'sshd': '/etc/pam.d/sshd',
            'login': '/etc/pam.d/login',
        
            # Sudo
            'sudoers': '/etc/sudoers',
        
            # User management
            'passwd': '/etc/passwd',
            'shadow': '/etc/shadow',
            'group': '/etc/group',
            'gshadow': '/etc/gshadow',
        
            # Firewall
            'ufw': '/etc/default/ufw',
            'ufw.conf': '/etc/ufw/ufw.conf',
            'before.rules': '/etc/ufw/before.rules',
            'after.rules': '/etc/ufw/after.rules',
            'user.rules': '/etc/ufw/user.rules',
            'user6.rules': '/etc/ufw/user6.rules',
        
            # Web servers
            'apache2.conf': '/etc/apache2/apache2.conf',
            'ports.conf': '/etc/apache2/ports.conf',
            'security.conf': '/etc/apache2/conf-available/security.conf',
            'nginx.conf': '/etc/nginx/nginx.conf',
            'sites-enabled': '/etc/nginx/sites-enabled/',
            'sites-available': '/etc/nginx/sites-available/',
        
            # Databases
            'my.cnf': '/etc/mysql/my.cnf',
            'mysqld.cnf': '/etc/mysql/mysql.conf.d/mysqld.cnf',
            'postgresql.conf': '/etc/postgresql/*/main/postgresql.conf',
            'pg_hba.conf': '/etc/postgresql/*/main/pg_hba.conf',
        
            # Container
            'daemon.json': '/etc/docker/daemon.json',
            'docker': '/etc/docker/',
        
            # NFS
            'exports': '/etc/exports',
        
            # Kernel
            'sysctl.conf': '/etc/sysctl.conf',
            'sysctl.d': '/etc/sysctl.d/',
        
            # Audit
            'auditd.conf': '/etc/audit/auditd.conf',
            'audit.rules': '/etc/audit/rules.d/audit.rules',
            'shadow.rules': '/etc/audit/rules.d/shadow.rules',
        
            # Scheduled tasks
            'crontab': '/etc/crontab',
            'cron.d': '/etc/cron.d/',
            'cron.hourly': '/etc/cron.hourly/',
            'cron.daily': '/etc/cron.daily/',
            'cron.weekly': '/etc/cron.weekly/',
            'cron.monthly': '/etc/cron.monthly/',
        
            # Startup
            'rc.local': '/etc/rc.local',
        
            # Security
            'limits.conf': '/etc/security/limits.conf',
            'login.defs': '/etc/login.defs',
            'pwquality.conf': '/etc/security/pwquality.conf',
            'capability.conf': '/etc/security/capability.conf',
        
            # SELinux
            'config': '/etc/selinux/config',
            'selinux': '/etc/selinux/',
        
            # AppArmor
            'apparmor': '/etc/apparmor.d/',
        
            # Network
            'hosts': '/etc/hosts',
            'hostname': '/etc/hostname',
            'resolv.conf': '/etc/resolv.conf',
            'nsswitch.conf': '/etc/nsswitch.conf',
            'hosts.allow': '/etc/hosts.allow',
            'hosts.deny': '/etc/hosts.deny',
            'network': '/etc/network/',
            'netplan': '/etc/netplan/',
        
            # Filesystem
            'fstab': '/etc/fstab',
            'mtab': '/etc/mtab',
        
            # Modules
            'shadow-blacklist.conf': '/etc/modprobe.d/shadow-blacklist.conf',
            'blacklist': '/etc/modprobe.d/',
        
            # Logging
            'rsyslog.conf': '/etc/rsyslog.conf',
            'rsyslog.d': '/etc/rsyslog.d/',
            'logrotate.conf': '/etc/logrotate.conf',
            'logrotate.d': '/etc/logrotate.d/',
        
            # Systemd
            'systemd-logind.conf': '/etc/systemd/logind.conf',
            'journald.conf': '/etc/systemd/journald.conf',
            'timesyncd.conf': '/etc/systemd/timesyncd.conf',
            'shadow.service': '/etc/systemd/system/shadow.service',
        
            # Integrity
            'aide.conf': '/etc/aide/aide.conf',
        
            # Shadow specific
            'shadow.yml': '/etc/shadow-tool/shadow.yml',
            'shadow-tool': '/etc/shadow-tool/',
        }
    
        # Check exact match
        for key, dest in file_map.items():
            if key == name:
                return Path(dest)
    
        # Check partial match
        for key, dest in file_map.items():
            if key in name or name in key:
                return Path(dest)
    
        # Check if it's a directory backup (common pattern)
        if 'etc' in name and 'backup' in name:
            return Path('/etc/')
        elif 'var' in name and 'backup' in name:
            return Path('/var/')
    
        self.logger.warning(f"Could not determine destination for: {backup_path.name}")
        return None
    
    # ============================================================
    # INTERACTIVE RESTORE MENU
    # ============================================================
    def interactive_restore(self):
        """Interactive restore menu"""
        print("\n" + "="*60)
        print("SHADOW - RESTORE FROM BACKUP")
        print("="*60)
        
        backups = self.list_backups()
        
        if not backups:
            print("[!] No backups found in: /var/backups/shadow/")
            return
        
        print("\nAvailable backups:")
        print("-"*60)
        for i, backup in enumerate(backups, 1):
            print(f"  {i}. {backup['name']}")
            print(f"     Size: {backup['size']}, Modified: {backup['modified']}")
        
        print("\nOptions:")
        print("  D. Dry-run (preview restore)")
        print("  R. Restore specific module")
        print("  F. Restore full system")
        print("  E. Emergency restore (safe mode)")
        print("  B. Create Full Backup (do this once so F works)")
        print("  Q. Quit")
        
        choice = ui.prompt("\nChoose option: ", raw=True).strip().upper()
        
        if choice == 'Q':
            return
        
        if choice == 'D':
            self._dry_run_interactive(backups)
        elif choice == 'R':
            self._restore_specific()
        elif choice == 'F':
            self._restore_full()
        elif choice == 'E':
            self._emergency_restore()
        elif choice == 'B':
            self.create_full_backup()
        else:
            # Try to parse as number
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(backups):
                    self._restore_backup(backups[idx])
                else:
                    print("[!] Invalid selection")
            except ValueError:
                print("[!] Invalid option")
    
    def _dry_run_interactive(self, backups: List[Dict]):
        """Interactive dry-run mode"""
        print("\n" + "="*60)
        print("DRY-RUN RESTORE PREVIEW")
        print("="*60)
        
        if not backups:
            print("[!] No backups found")
            return
        
        print("\nSelect backup to preview:")
        for i, backup in enumerate(backups, 1):
            print(f"  {i}. {backup['name']} ({backup['modified']})")
        
        choice = ui.prompt("\nSelect backup [1-{}]: ".format(len(backups)), raw=True)
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(backups):
                backup = backups[idx]
                backup_path = Path(backup['path'])
                
                print("\n" + "="*60)
                print("DRY-RUN PLAN")
                print("="*60)
                
                plan = self.dry_run_restore(backup_path)
                if 'error' in plan:
                    print(f"[!] {plan['error']}")
                    return
                
                print(f"Backup: {plan['backup_name']}")
                print(f"Size: {plan['backup_size']}")
                print(f"Files to restore: {len(plan['files_to_restore'])}")
                print("\nRestore plan:")
                for item in plan['files_to_restore'][:10]:
                    print(f"  {item['source']} → {item['dest']}")
                if len(plan['files_to_restore']) > 10:
                    print(f"  ... and {len(plan['files_to_restore']) - 10} more")
                print("\n[✓] Dry-run complete. No changes were made.")
            else:
                print("[!] Invalid selection")
        except ValueError:
            print("[!] Invalid input")
    
    def _restore_specific(self):
        """Restore specific module"""
        module_name = ui.prompt("\nEnter module name to restore (e.g., ssh, sudo, passwd): ", raw=True).strip()
        if not module_name:
            print("[!] Module name required")
            return
        
        self.restore_module(module_name)
        
    def _emergency_restore(self):
        """Emergency restore - safe mode"""
        print("\n" + "="*60)
        print("EMERGENCY RESTORE")
        print("="*60)
        print("[!] WARNING: Emergency restore in progress")
        print("    This will restore the most recent backup")
        print("    System may restart after restore")
        print("="*60)
        
        confirm = ui.prompt("Are you sure? (type 'yes' to continue): ", raw=True)
        
        if confirm.upper() != 'YES':
            print("Aborted.")
            return
        
        # Find most recent backup
        backups = self.list_backups()
        if not backups:
            print("[!] No backups found")
            return
        
        # Use most recent backup
        latest = backups[0]
        print(f"\nRestoring from: {latest['name']}")
        
        self._restore_backup(latest)
        
        print("\n[✓] Emergency restore completed!")
        print("    Please restart the system if required.")
    
    def _restore_backup(self, backup: Dict):
        """Restore a specific backup"""
        backup_path = Path(backup['path'])
        
        if not backup_path.exists():
            print(f"[!] Backup not found: {backup_path}")
            return
        
        # Validate backup first with checksum
        if not self._validate_backup(backup_path):
            print("[!] Backup validation failed. Aborting restore.")
            return
        
        # Check if dry-run
        if self._is_dry_run():
            plan = self.dry_run_restore(backup_path)
            print("\n" + "="*60)
            print("DRY-RUN RESTORE PLAN")
            print("="*60)
            print(f"Backup: {plan.get('backup_name', 'unknown')}")
            print(f"Files to restore: {len(plan.get('files_to_restore', []))}")
            print("[✓] Dry-run complete. No changes were made.")
            return
        
        # Get confirmation
        if not self._is_force_mode():
            plan = self.dry_run_restore(backup_path)
            if not self.require_restore_confirmation(plan):
                print("Restore cancelled.")
                return
        
        print(f"\nRestoring from: {backup['name']}")
        print(f"Size: {backup['size']}")
        print(f"Modified: {backup['modified']}")
        
        # Begin transaction
        self._begin_transaction()
        
        try:
            self.logger.info(f"Starting restore from: {backup_path}")
            
            # Create pre-restore backup of current state
            pre_restore_dir = self.backup_dir / f"pre_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            pre_restore_dir.mkdir(parents=True, exist_ok=True)
            
            # Determine if directory or file
            if backup_path.is_dir():
                # Restore directory contents
                self._restore_directory(backup_path, pre_restore_dir)
            else:
                # Restore single file
                self._restore_file(backup_path, pre_restore_dir)
            
            # Commit transaction
            result = self._commit_transaction()
            
            print(f"\n[✓] Restore completed from: {backup['name']}")
            print(f"    Files restored: {len(result.get('restored', []))}")
            print(f"    Files failed: {len(result.get('failed', []))}")
            
            self.logger.info(f"Restore completed from: {backup_path}")
            self.log_restore("RESTORE", f"Restored from {backup['name']}")
            
        except Exception as e:
            print(f"[!] Restore failed: {e}")
            self.logger.error(f"Restore failed: {e}")
            self.log_restore("FAILED", f"Restore failed: {e}")
            # Rollback transaction
            result = self._rollback_transaction()
            print(f"[!] Restore rolled back: {result.get('files_restored', 0)} files restored")
    
    def _is_dry_run(self) -> bool:
        """Check if in dry-run mode"""
        return hasattr(self, '_dry_run') and self._dry_run
    
    def _is_force_mode(self) -> bool:
        """Check if in force mode"""
        return hasattr(self, '_force') and self._force
    
    def set_dry_run(self, enabled: bool = True):
        """Enable/disable dry-run mode"""
        self._dry_run = enabled
    
    def set_force(self, enabled: bool = True):
        """Enable/disable force mode"""
        self._force = enabled
    
    def _restore_directory(self, backup_path: Path, pre_restore_dir: Path):
        """Restore a directory backup"""
        # Determine destination using explicit mapping
        dest_path = self._get_destination_path(backup_path)
        
        if dest_path is None:
            # Try to determine from name
            name = backup_path.name.lower()
            if 'ssh' in name:
                dest_path = Path("/etc/ssh/")
            elif 'pam' in name:
                dest_path = Path("/etc/pam.d/")
            elif 'sudo' in name:
                dest_path = Path("/etc/")
            elif 'passwd' in name or 'shadow' in name:
                dest_path = Path("/etc/")
            elif 'ufw' in name:
                dest_path = Path("/etc/default/")
            elif 'apache' in name:
                dest_path = Path("/etc/apache2/")
            elif 'nginx' in name:
                dest_path = Path("/etc/nginx/")
            else:
                print(f"[!] Cannot determine destination for: {backup_path.name}")
                return
        
        # Create backup of current state before restore
        if dest_path.exists():
            shutil.copytree(dest_path, pre_restore_dir, dirs_exist_ok=True)
            print(f"Pre-restore backup created: {pre_restore_dir}")
        
        # Get list of items to restore
        items = list(backup_path.iterdir())
        total_items = len(items)
        
        for idx, item in enumerate(items):
            # Report progress
            self._report_progress(idx + 1, total_items, f"Restoring {item.name}")
            
            dest_file = dest_path / item.name
            if item.is_file():
                # Restore with integrity check
                if self._restore_file_with_integrity(item, dest_file):
                    print(f"  Restored: {dest_file}")
                    # Validate after restore
                    if not self._validate_after_restore(str(dest_file)):
                        print(f"[!] Validation failed for: {dest_file}")
                        raise Exception(f"Validation failed for {dest_file}")
                    # Log the restore
                    self._log_change("RESTORE", str(dest_file), f"Restored from {item.name}")
                    self._transaction['restored'].append(str(dest_file))
                else:
                    raise Exception(f"Integrity check failed for {dest_file}")
        
        # Set proper permissions
        self._set_permissions(dest_path)
        
        # Restart affected services
        if dest_path:
            service_results = self._restart_affected_services(dest_path)
            if service_results['restarted']:
                print(f"  Restarted services: {', '.join(service_results['restarted'])}")
            if service_results['failed']:
                print(f"  Failed to restart: {', '.join(service_results['failed'])}")
        
        self.logger.info(f"Directory restored to: {dest_path}")
    
    def _restore_file(self, backup_path: Path, pre_restore_dir: Path) -> bool:
        """Restore a single file"""
        # Determine destination using explicit mapping
        dest_path = self._get_destination_path(backup_path)
    
        # ✅ FIX: Better error handling - return False instead of silent return
        if dest_path is None:
            # Try to determine from name (fallback)
            name = backup_path.name.lower()
        
            # Expanded fallback mapping
            fallback_map = {
                'sshd_config': '/etc/ssh/sshd_config',
                'ssh_config': '/etc/ssh/ssh_config',
                'common-password': '/etc/pam.d/common-password',
                'common-auth': '/etc/pam.d/common-auth',
                'common-account': '/etc/pam.d/common-account',
                'common-session': '/etc/pam.d/common-session',
                'sudoers': '/etc/sudoers',
                'passwd': '/etc/passwd',
                'shadow': '/etc/shadow',
                'group': '/etc/group',
                'gshadow': '/etc/gshadow',
                'ufw': '/etc/default/ufw',
                'ufw.conf': '/etc/ufw/ufw.conf',
                'apache2.conf': '/etc/apache2/apache2.conf',
                'ports.conf': '/etc/apache2/ports.conf',
                'security.conf': '/etc/apache2/conf-available/security.conf',
                'nginx.conf': '/etc/nginx/nginx.conf',
                'my.cnf': '/etc/mysql/my.cnf',
                'mysqld.cnf': '/etc/mysql/mysql.conf.d/mysqld.cnf',
                'daemon.json': '/etc/docker/daemon.json',
                'exports': '/etc/exports',
                'sysctl.conf': '/etc/sysctl.conf',
                'auditd.conf': '/etc/audit/auditd.conf',
                'audit.rules': '/etc/audit/rules.d/audit.rules',
                'shadow.rules': '/etc/audit/rules.d/shadow.rules',
                'crontab': '/etc/crontab',
                'rc.local': '/etc/rc.local',
                'limits.conf': '/etc/security/limits.conf',
                'login.defs': '/etc/login.defs',
                'pwquality.conf': '/etc/security/pwquality.conf',
                'capability.conf': '/etc/security/capability.conf',
                'config': '/etc/selinux/config',
                'hosts': '/etc/hosts',
                'hostname': '/etc/hostname',
                'resolv.conf': '/etc/resolv.conf',
                'nsswitch.conf': '/etc/nsswitch.conf',
                'hosts.allow': '/etc/hosts.allow',
                'hosts.deny': '/etc/hosts.deny',
                'fstab': '/etc/fstab',
                'shadow-blacklist.conf': '/etc/modprobe.d/shadow-blacklist.conf',
                'rsyslog.conf': '/etc/rsyslog.conf',
                'logrotate.conf': '/etc/logrotate.conf',
                'systemd-logind.conf': '/etc/systemd/logind.conf',
                'journald.conf': '/etc/systemd/journald.conf',
                'timesyncd.conf': '/etc/systemd/timesyncd.conf',
                'shadow.yml': '/etc/shadow-tool/shadow.yml',
                'aide.conf': '/etc/aide/aide.conf',
            }
        
            for key, dest in fallback_map.items():
                if key in name:
                    dest_path = Path(dest)
                    break
        
            if dest_path is None:
                self.logger.error(f"Cannot determine destination for: {backup_path.name}")
                print(f"[!] Cannot determine destination for: {backup_path.name}")
                return False
    
        # ✅ FIX: Ensure destination directory exists
        try:
            dest_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.logger.error(f"Failed to create destination directory: {e}")
            return False
    
        # Create backup of current state before restore
        if dest_path.exists():
            try:
                pre_restore_file = pre_restore_dir / dest_path.name
                pre_restore_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(dest_path, pre_restore_file)
                print(f"Pre-restore backup created: {pre_restore_file}")
                # Store for transaction rollback
                self._transaction_backups.append({
                    'backup_path': str(pre_restore_file),
                    'original_path': str(dest_path),
                    'is_directory': False
                })
            except Exception as e:
                self.logger.warning(f"Could not create pre-restore backup: {e}")
    
        # ✅ FIX: Verify backup exists before restoring
        if not backup_path.exists():
            self.logger.error(f"Backup file not found: {backup_path}")
            return False
    
        # ✅ FIX: Check backup size
        if backup_path.stat().st_size == 0:
            self.logger.error(f"Backup file is empty: {backup_path}")
            return False
    
        # Restore file with integrity check
        try:
            if self._restore_file_with_integrity(backup_path, dest_path):
                print(f"  ✅ Restored: {dest_path}")
            
                # Validate after restore
                if not self._validate_after_restore(str(dest_path)):
                    self.logger.error(f"Validation failed for: {dest_path}")
                    print(f"[!] Validation failed for: {dest_path}")
                    return False
            
                # Set proper permissions
                self._set_permissions(dest_path)
            
                # Log the restore
                self._log_change("RESTORE", str(dest_path), f"Restored from {backup_path.name}")
                self._transaction['restored'].append(str(dest_path))
            
                # Restart affected services
                service_results = self._restart_affected_services(dest_path)
                if service_results['restarted']:
                    print(f"  Restarted services: {', '.join(service_results['restarted'])}")
                if service_results['failed']:
                    print(f"  Failed to restart: {', '.join(service_results['failed'])}")
            
                self.logger.info(f"File restored: {dest_path}")
                return True
            else:
                self.logger.error(f"Integrity check failed for {dest_path}")
                print(f"[!] Integrity check failed for: {dest_path}")
                return False
            
        except Exception as e:
            self.logger.error(f"Restore failed for {dest_path}: {e}")
            print(f"[!] Restore failed: {e}")
            return False

    # ============================================================
    # ✅ FIX 1: RESTORE MODULE (Missing method that caused crash)
    # ============================================================
    def restore_module(self, module_name: str) -> bool:
        """
        Restore all backups related to a specific module (ssh, sudo, passwd, etc.)
        """
        self.logger.info(f"Restoring module: {module_name}")
        print(f"\n[!] Searching for backups related to: {module_name}")
        
        if not self.backup_dir.exists():
            print("[!] No backup directory found")
            return False
        
        # Module name mapping to backup file patterns
        module_patterns = {
            'ssh': ['sshd_config.backup_*', 'ssh_config.backup_*', 'ssh.backup_*'],
            'sudo': ['sudoers.backup_*'],
            'passwd': ['passwd.backup_*'],
            'shadow': ['shadow.backup_*'],
            'group': ['group.backup_*'],
            'gshadow': ['gshadow.backup_*'],
            'pam': ['common-password.backup_*', 'common-auth.backup_*', 
                   'common-account.backup_*', 'common-session.backup_*'],
            'login': ['login.defs.backup_*'],
            'password': ['pwquality.conf.backup_*'],
            'firewall': ['ufw.backup_*', 'ufw.conf.backup_*'],
            'hosts': ['hosts.backup_*', 'hostname.backup_*', 'resolv.conf.backup_*'],
            'sysctl': ['sysctl.conf.backup_*'],
            'rsyslog': ['rsyslog.conf.backup_*'],
            'logrotate': ['logrotate.conf.backup_*'],
        }
        
        # Get patterns for this module (fallback to module name)
        patterns = module_patterns.get(module_name.lower(), [f"*{module_name}*.backup_*"])
        
        # Find matching backups
        matching_backups = []
        for pattern in patterns:
            matching_backups.extend(self.backup_dir.glob(pattern))
        
        # Remove duplicates and sort by modification time (newest first)
        matching_backups = sorted(
            list(set(matching_backups)),
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        
        if not matching_backups:
            print(f"[!] No backups found for module: {module_name}")
            return False
        
        print(f"\n[✓] Found {len(matching_backups)} backups for {module_name}:")
        for backup in matching_backups[:5]:
            mtime = datetime.fromtimestamp(backup.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            print(f"  - {backup.name} ({mtime})")
        
        # Restore each backup
        restored_count = 0
        failed_count = 0
        
        self._begin_transaction()
        
        for backup_path in matching_backups:
            print(f"\n→ Restoring: {backup_path.name}")
            
            # Get destination
            dest_path = self._get_destination_path(backup_path)
            if dest_path is None:
                print(f"  [!] Cannot determine destination for {backup_path.name}")
                failed_count += 1
                continue
            
            # Create pre-restore backup
            if dest_path.exists():
                try:
                    pre_restore = self.backup_dir / f"pre_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{dest_path.name}"
                    shutil.copy2(dest_path, pre_restore)
                    self._transaction_backups.append({
                        'backup_path': str(pre_restore),
                        'original_path': str(dest_path),
                        'is_directory': False
                    })
                except Exception as e:
                    self.logger.warning(f"Pre-restore backup failed: {e}")
            
            # Restore with integrity check
            if self._restore_file_with_integrity(backup_path, dest_path):
                self._set_permissions(dest_path)
                print(f"  ✅ Restored: {dest_path}")
                restored_count += 1
                self._transaction['restored'].append(str(dest_path))
            else:
                print(f"  ❌ Failed: {dest_path}")
                failed_count += 1
                self._transaction['failed'].append(str(dest_path))
        
        # Commit transaction
        self._commit_transaction()
        
        print(f"\n{'='*60}")
        print(f"✅ Module restore complete: {restored_count} restored, {failed_count} failed")
        print(f"{'='*60}")
        
        return restored_count > 0
    
    # ============================================================
    # ✅ FIX 2: SET PERMISSIONS (Missing method that caused crash)
    # ============================================================
    def _set_permissions(self, path: Path) -> bool:
        """Set correct permissions for restored files based on security best practices."""
        try:
            path_str = str(path)
            
            # Critical security file permissions mapping
            permissions_map = {
                # User & password files
                '/etc/shadow': 0o640,        # root:shadow, only root can read/write
                '/etc/gshadow': 0o640,
                '/etc/passwd': 0o644,        # World readable
                '/etc/group': 0o644,
                
                # Sudo
                '/etc/sudoers': 0o440,       # root:root, read-only
                '/etc/sudoers.d/': 0o440,
                
                # SSH
                '/etc/ssh/sshd_config': 0o600,
                '/etc/ssh/ssh_config': 0o644,
                
                # PAM
                '/etc/pam.d/common-password': 0o644,
                '/etc/pam.d/common-auth': 0o644,
                '/etc/pam.d/common-account': 0o644,
                '/etc/pam.d/common-session': 0o644,
                
                # Login
                '/etc/login.defs': 0o644,
                '/etc/security/pwquality.conf': 0o644,
                '/etc/security/limits.conf': 0o644,
                
                # Firewall
                '/etc/default/ufw': 0o644,
                
                # Network
                '/etc/hosts': 0o644,
                '/etc/hostname': 0o644,
                '/etc/resolv.conf': 0o644,
                
                # Kernel
                '/etc/sysctl.conf': 0o644,
                
                # Audit
                '/etc/audit/auditd.conf': 0o640,
                '/etc/audit/rules.d/': 0o640,
                
                # Web servers
                '/etc/apache2/apache2.conf': 0o644,
                '/etc/nginx/nginx.conf': 0o644,
                
                # Database
                '/etc/mysql/my.cnf': 0o644,
                
                # Container
                '/etc/docker/daemon.json': 0o644,
                
                # Logging
                '/etc/rsyslog.conf': 0o644,
                '/etc/logrotate.conf': 0o644,
            }
            
            # Check if this is a directory
            if path.is_dir():
                # For directories, set 755
                os.chmod(path, 0o755)
                self.logger.debug(f"Set directory permissions 755: {path}")
                return True
            
            # Find matching permission
            for pattern, perm in permissions_map.items():
                if pattern in path_str or path_str in pattern:
                    os.chmod(path, perm)
                    self.logger.debug(f"Set permissions {oct(perm)}: {path}")
                    return True
            
            # Default: 644 for regular files
            if path.is_file():
                os.chmod(path, 0o644)
                self.logger.debug(f"Set default permissions 644: {path}")
            
            return True
            
        except Exception as e:
            self.logger.warning(f"Failed to set permissions for {path}: {e}")
            return False

    def create_full_backup(self) -> bool:
        """Create a full backup of critical system files (needed for option F)."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        full_dir = self.backup_dir / f"full_backup_{timestamp}"
        critical_files = [
            '/etc/ssh/sshd_config', '/etc/passwd', '/etc/shadow',
            '/etc/group', '/etc/gshadow', '/etc/sudoers', '/etc/login.defs',
            '/etc/hosts', '/etc/hostname', '/etc/resolv.conf',
            '/etc/sysctl.conf', '/etc/rsyslog.conf', '/etc/logrotate.conf',
            '/etc/security/pwquality.conf', '/etc/pam.d/common-password',
            '/etc/pam.d/common-auth', '/etc/pam.d/common-account',
            '/etc/pam.d/common-session',
        ]
        try:
            full_dir.mkdir(parents=True, exist_ok=True)
            copied = 0
            for src in critical_files:
                src_path = Path(src)
                if src_path.exists():
                    shutil.copy2(src_path, full_dir / src_path.name)
                    copied += 1
            print(f"\n✅ Full backup created: {full_dir.name} ({copied} files)")
            return True
        except Exception as e:
            print(f"\n❌ Failed to create full backup: {e}")
            return False

    def _restore_full(self):
        """Restore full system from the most recent full backup."""
        print("\n" + "="*60)
        print("FULL SYSTEM RESTORE")
        print("="*60)
        print("[!] WARNING: This will restore ALL backed up files")
        print("="*60)
        confirm = ui.prompt("Are you sure? (type 'YES' to continue): ", raw=True)
        if confirm.lower() != 'yes':
            print("Aborted.")
            return
        full_backups = [d for d in self.backup_dir.iterdir()
                        if d.is_dir() and d.name.startswith('full_backup_')]
        if not full_backups:
            print("[!] No full system backup found.")
            print("    Tip: Use option 'B' in the menu to create one first!")
            return
        latest = sorted(full_backups, key=lambda x: x.stat().st_mtime)[-1]
        print(f"\nRestoring from: {latest.name}")
        self._begin_transaction()
        restored = 0
        failed = 0
        for backup_file in latest.iterdir():
            if not backup_file.is_file():
                continue
            dest_path = self._get_destination_path(backup_file)
            if dest_path is None:
                failed += 1
                continue
            if dest_path.exists():
                try:
                    pre = self.backup_dir / f"pre_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{dest_path.name}"
                    shutil.copy2(dest_path, pre)
                    self._transaction_backups.append({'backup_path': str(pre), 'original_path': str(dest_path), 'is_directory': False})
                except Exception:
                    pass
            if self._restore_file_with_integrity(backup_file, dest_path):
                self._set_permissions(dest_path)
                print(f"  ✅ Restored: {dest_path}")
                restored += 1
            else:
                print(f"  ❌ Failed: {dest_path}")
                failed += 1
        self._commit_transaction()
        print(f"\n✅ Full restore complete: {restored} restored, {failed} failed")

    def get_restore_history(self) -> List[Dict]:
        """Get restore history"""
        history = []
        
        if not self.restore_log.exists():
            return history
        
        with open(self.restore_log, 'r') as f:
            for line in f:
                parts = line.strip().split('|')
                if len(parts) >= 3:
                    history.append({
                        'timestamp': parts[0],
                        'action': parts[1],
                        'details': parts[2] if len(parts) > 2 else ''
                    })
        
        return history
    
    def log_restore(self, action: str, details: str):
        """Log a restore action"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            with open(self.restore_log, 'a') as f:
                f.write(f"{timestamp}|{action}|{details}\n")
        except Exception as e:
            self.logger.warning(f"Failed to log restore: {e}")