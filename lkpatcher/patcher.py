"""
SPDX-FileCopyrightText: 2025 Roger Ortiz <me@r0rt1z2.com>
SPDX-License-Identifier: GPL-3.0-or-later
"""

from __future__ import annotations

import json
import logging
import re
import struct
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, cast

from liblk.exceptions import NeedleNotFoundException
from liblk.image import LkImage
from liblk.structures.partition import LkPartition

from lkpatcher.config import PatcherConfig
from lkpatcher.exceptions import (
    ConfigurationError,
    InvalidIOFile,
    NoNeedlesFound,
    PatchValidationError,
)
from lkpatcher.policy import patch_lk_security_policies


class PatchManager:
    """
    Manages patches for LK bootloader images.

    Handles loading patches from built-in defaults or custom JSON files,
    validates patch formats, and provides utilities to work with patch collections.

    Attributes:
        patches: Dictionary of patches organized by category
        patches_count: Total number of individual patches loaded
    """

    DEFAULT_PATCHES: Dict[str, Dict[str, str]] = {
        # Unlock fastboot access by forcing the function
        # that checks for the unlock bit in oplusreserve
        # to always return 0 (unlocked)
        'fastboot': {
            '2de9f04fadf5ac5d': '00207047',
            'f0b5adf5925d': '00207047',
        },
        # Disable warning message that shows up when the device
        # gets unlocked with mtkclient by forcing the function
        # that checks for vbmeta state to always return 0
        'dm_verity': {
            '30b583b002ab0022': '00207047',
        },
        # Disable warning message that shows up when the device
        # gets unlocked by forcing the function that checks for
        # the current LCS state to always return 0
        'orange_state': {
            '08b50a4b7b441b681b68022b': '00207047',
            '08b50e4b7b441b681b68022b': '00207047',
        },
        # Force the function that prints the warning about
        # device verification to return immediately
        'red_state': {
            'f0b5002489b0': '00207047',
        },
    }

    def __init__(
        self,
        patches_file: Optional[Path] = None,
        config: Optional[PatcherConfig] = None,
    ) -> None:
        """
        Initialize the patch manager.

        Args:
            patches_file: Optional path to a JSON file with custom patches
            config: Optional configuration object
        """
        self.logger = logging.getLogger(__name__)
        self.patches: Dict[str, Dict[str, str]] = self.DEFAULT_PATCHES.copy()
        self.config = config or PatcherConfig()

        if patches_file:
            self.load_patches(patches_file)

        if self.config.verify_patch:
            self._validate_patches()

        self.patches_count = len(self.get_all_patches())
        self.logger.info(
            'Successfully loaded %d patches in %d categories',
            self.patches_count,
            len(self.patches),
        )

    def load_patches(self, file_path: Path) -> None:
        """
        Load patches from a JSON file.

        The file can either completely replace the default patches or
        add/update specific categories.

        Args:
            file_path: Path to the JSON file with patches

        Raises:
            InvalidIOFile: If the file cannot be read or parsed
            ConfigurationError: If the patch file has an invalid format
        """
        try:
            with open(file_path, 'r') as fp:
                patch_data = json.load(fp)

            if not isinstance(patch_data, dict):
                raise ConfigurationError(
                    'Patch file must contain a JSON object', file_path
                )

            mode = patch_data.pop('mode', 'update').lower()

            if mode == 'replace':
                self.patches = {}

            for category, patches in patch_data.items():
                if category == 'mode':
                    continue

                if not isinstance(patches, dict):
                    self.logger.warning(
                        "Skipping invalid category '%s': patches must be a dictionary",
                        category,
                    )
                    continue

                if category not in self.patches:
                    self.patches[category] = {}

                if mode == 'update':
                    self.patches[category].update(patches)
                else:
                    self.patches[category] = patches

        except FileNotFoundError:
            self.logger.warning('Patch file not found: %s', file_path)
        except json.JSONDecodeError as e:
            raise InvalidIOFile(f'Invalid JSON: {e}', file_path)

    def _validate_patches(self) -> None:
        """
        Validate all patch formats.

        Ensures that all needles and patches are valid hexadecimal strings.

        Raises:
            PatchValidationError: If a patch fails validation
        """
        hex_pattern = re.compile(r'^[0-9a-fA-F]+$')

        for category, patches in self.patches.items():
            for needle, patch in patches.items():
                if not hex_pattern.match(needle):
                    raise PatchValidationError(
                        needle,
                        patch,
                        f"Needle in category '{category}' is not a valid hex string",
                    )

                if not hex_pattern.match(patch):
                    raise PatchValidationError(
                        needle,
                        patch,
                        f"Patch in category '{category}' is not a valid hex string",
                    )

    def get_all_patches(self) -> List[str]:
        """
        Get a flat list of all patch needles.

        Returns:
            List of all unique patch needles
        """
        return [
            needle
            for category in self.patches.values()
            for needle in category.keys()
        ]

    def get_applicable_patches(self) -> Dict[str, Dict[str, str]]:
        """
        Get patches that should be applied based on configuration.

        Filters patches according to include/exclude categories in config.

        Returns:
            Dictionary of patches to apply
        """
        result: Dict[str, Dict[str, str]] = {}

        for category, patches in self.patches.items():
            if self.config.should_apply_category(category):
                result[category] = patches.copy()

        return result

    def export_patches(self, file_path: Path) -> None:
        """
        Export current patches to a JSON file.

        Args:
            file_path: Path where patches will be saved

        Raises:
            InvalidIOFile: If file cannot be written
        """
        try:
            with open(file_path, 'w') as fp:
                json.dump(self.patches, fp, indent=4)
        except OSError as e:
            raise InvalidIOFile(str(e), file_path)


class LkPatcher:
    """
    Patches MediaTek bootloader (LK) images.

    Applies binary patches to modify bootloader behavior, allowing
    for features like unlocking fastboot, disabling verification
    warnings, etc.

    Attributes:
        image: LkImage instance representing the bootloader
        patch_manager: Manager for available patches
        config: Configuration settings for the patcher
    """

    def __init__(
        self,
        image: Union[str, Path],
        patches: Optional[Path] = None,
        config: Optional[PatcherConfig] = None,
        load_image: bool = True,
    ) -> None:
        """
        Initialize the LK patcher.

        Args:
            image: Path to the bootloader image
            patches: Optional path to JSON file with custom patches
            config: Optional configuration settings
            load_image: Whether to load the image immediately
        """
        self.logger = logging.getLogger(__name__)
        self.config = config or PatcherConfig()
        self.patch_manager = PatchManager(patches, self.config)

        if load_image:
            self.image = LkImage(image)
            self.logger.info(
                'Loaded image from %s with %d partitions (version %d)',
                image,
                len(self.image.partitions),
                self.image.version,
            )
        else:
            self.image = cast(LkImage, None)

    def _rebuild_image_contents(self) -> None:
        """
        Rebuild the main image contents from modified partitions.
        This ensures that partition-level changes are reflected in the main image.
        """
        new_contents = bytearray()
        partition_names = list(self.image.partitions.keys())

        for i, (name, partition) in enumerate(self.image.partitions.items()):
            partition.header.image_list_end = (
                1 if i == len(partition_names) - 1 else 0
            )
            partition.end_offset = (
                len(new_contents)
                + partition.header.size
                + partition.header.data_size
            )

            alignment = (
                partition.header.alignment
                if partition.header.is_extended
                else 8
            )
            if alignment and partition.end_offset % alignment:
                partition.end_offset += alignment - (
                    partition.end_offset % alignment
                )

            new_contents.extend(bytes(partition))

        self.image.contents = new_contents

    def patch(
        self, output: Union[str, Path], patch_policies: bool = False
    ) -> Path:
        """
        Patch the bootloader image.

        Attempts to apply all available patches to the bootloader
        and saves the modified image to the specified output path.

        Args:
            output: Path where the patched image will be saved
            patch_policies: Whether to patch security policies

        Returns:
            Path to the saved patched image

        Raises:
            NoNeedlesFound: If no patches could be applied
            InvalidIOFile: If the output file cannot be written
        """
        applicable_patches = self.patch_manager.get_applicable_patches()

        if not applicable_patches and not patch_policies:
            self.logger.warning(
                'No applicable patches based on current configuration'
            )
            if self.config.dry_run:
                return Path(output)
            else:
                raise NoNeedlesFound(self.image.path or 'Unknown')

        self.logger.info(
            'Starting patching process with %d categories',
            len(applicable_patches),
        )

        total_patches = sum(
            len(patches) for patches in applicable_patches.values()
        )
        applied_count = 0
        skipped_count = 0

        results: Dict[str, Dict[str, bool]] = {}

        if self.image.contents:
            original_digest = sha256(self.image.contents).hexdigest()
            self.logger.debug('Original image SHA-256: %s', original_digest)

        for category, patches in list(applicable_patches.items()):
            category_results: Dict[str, bool] = {}
            results[category] = category_results

            self.logger.info(
                'Processing category: %s (%d patches)', category, len(patches)
            )

            for needle, patch in list(patches.items()):
                if self.config.dry_run:
                    self.logger.info(
                        'DRY RUN: Would apply patch %s -> %s',
                        needle[:10] + '...' if len(needle) > 10 else needle,
                        patch[:10] + '...' if len(patch) > 10 else patch,
                    )
                    category_results[needle] = True
                    applied_count += 1
                    continue

                try:
                    self.image.apply_patch(needle, patch)
                    category_results[needle] = True
                    applied_count += 1
                    self.logger.debug(
                        'Successfully applied patch %s -> %s',
                        needle[:10] + '...' if len(needle) > 10 else needle,
                        patch[:10] + '...' if len(patch) > 10 else patch,
                    )
                except NeedleNotFoundException:
                    category_results[needle] = False
                    skipped_count += 1
                    self.logger.debug('Needle not found: %s', needle)

        if patch_policies:
            lk_partition = self.image.partitions.get('lk')
            if lk_partition:
                if self.config.dry_run:
                    self.logger.info('DRY RUN: Would patch security policies')
                    results['security_policies'] = {'policy_patch': True}
                    applied_count += 1
                else:
                    try:
                        policy_patched = patch_lk_security_policies(
                            lk_partition
                        )
                        if policy_patched:
                            self.logger.info(
                                'Successfully patched security policies'
                            )
                            self._rebuild_image_contents()
                            results['security_policies'] = {
                                'policy_patch': True
                            }
                            applied_count += 1
                        else:
                            self.logger.warning(
                                'No security policies were patched'
                            )
                            results['security_policies'] = {
                                'policy_patch': False
                            }
                            skipped_count += 1
                    except Exception as e:
                        self.logger.error(
                            'Failed to patch security policies: %s', e
                        )
                        results['security_policies'] = {'policy_patch': False}
                        skipped_count += 1
            else:
                self.logger.warning(
                    'LK partition not found for policy patching'
                )

        self.logger.info(
            'Patching summary: %d/%d patches applied, %d skipped',
            applied_count,
            total_patches + (1 if patch_policies else 0),
            skipped_count,
        )

        if applied_count == 0 and not self.config.dry_run:
            debug_path = f'{self.image.path}.debug.txt'
            with open(debug_path, 'w') as fp:
                for partition_name, partition in self.image.partitions.items():
                    fp.write(f'{partition_name}:\n{partition}\n\n')

            self.logger.info(
                'Dumped partition info to %s for debugging', debug_path
            )

            if not self.config.allow_incomplete:
                raise NoNeedlesFound(self.image.path or 'Unknown')
            else:
                self.logger.warning(
                    'No patches were applied, but continuing due to allow_incomplete=True'
                )

        if self.image.contents and not self.config.dry_run:
            new_digest = sha256(self.image.contents).hexdigest()
            self.logger.debug('New image SHA-256: %s', new_digest)

            if new_digest == original_digest and applied_count > 0:
                self.logger.warning(
                    'Warning: Image digest unchanged despite applying patches'
                )

        if not self.config.dry_run:
            try:
                self.image.save(output)
                self.logger.info('Saved patched image to %s', output)
            except (FileNotFoundError, PermissionError) as e:
                raise InvalidIOFile(str(e), output)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = Path(output).with_suffix('.patch_report.json')
        try:
            with open(report_path, 'w') as fp:
                report = {
                    'timestamp': timestamp,
                    'image': str(self.image.path),
                    'image_version': self.image.version,
                    'total_patches': total_patches
                    + (1 if patch_policies else 0),
                    'applied_patches': applied_count,
                    'skipped_patches': skipped_count,
                    'dry_run': self.config.dry_run,
                    'security_policies_patched': patch_policies,
                    'results': results,
                }
                json.dump(report, fp, indent=4)
                self.logger.debug('Patch report saved to %s', report_path)
        except OSError:
            self.logger.warning(
                'Failed to write patch report to %s', report_path
            )

        return Path(output)

    def dump_partition(self, partition_name: str) -> Optional[Path]:
        """
        Dump a specific partition from the bootloader image.

        Args:
            partition_name: Name of the partition to dump

        Returns:
            Path to the dumped partition file, or None if partition not found

        Raises:
            InvalidIOFile: If the partition file cannot be written
        """
        partition = self.image.partitions.get(partition_name)

        if not partition:
            self.logger.error('Partition not found: %s', partition_name)
            self.logger.info(
                'Available partitions: %s', list(self.image.partitions.keys())
            )
            return None

        print('=' * 40)
        print(str(partition))
        print('=' * 40)

        if self.image.path:
            base_name = Path(self.image.path).stem
            output_path = f'{base_name}_{partition_name}.bin'
        else:
            output_path = f'{partition_name}.bin'

        try:
            partition.save(output_path)
            self.logger.info(
                'Successfully dumped partition %s to %s',
                partition_name,
                output_path,
            )
            return Path(output_path)
        except (FileNotFoundError, PermissionError) as e:
            raise InvalidIOFile(str(e), output_path)

    def extract_all_partitions(
        self, output_dir: Union[str, Path]
    ) -> List[Path]:
        """
        Extract all partitions from the bootloader image.

        Args:
            output_dir: Directory where partitions will be saved

        Returns:
            List of paths to saved partition files

        Raises:
            InvalidIOFile: If files cannot be written
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        saved_paths: List[Path] = []
        for partition_name, partition in self.image.partitions.items():
            safe_name = ''.join(
                c if c.isalnum() else '_' for c in partition_name
            )
            output_path = output_dir / f'{safe_name}.bin'

            try:
                partition.save(output_path)
                self.logger.info(
                    'Extracted partition %s to %s', partition_name, output_path
                )
                saved_paths.append(output_path)
            except (FileNotFoundError, PermissionError) as e:
                self.logger.error(
                    'Failed to extract partition %s: %s', partition_name, e
                )

        return saved_paths

    def analyze_image(self) -> Dict[str, Any]:
        """
        Perform analysis on the bootloader image.

        Gathers statistics and information about the image structure.

        Returns:
            Dictionary containing analysis results
        """
        if not self.image:
            return {'error': 'No image loaded'}

        partition_info = []
        total_size = len(self.image.contents) if self.image.contents else 0

        for name, partition in self.image.partitions.items():
            partition_info.append(
                {
                    'name': name,
                    'size': len(partition.data),
                    'has_ext_header': partition.header.is_extended,
                    'memory_address': f'0x{partition.header.memory_address:08x}',
                }
            )

        return {
            'image_path': str(self.image.path)
            if self.image.path
            else 'Unknown',
            'image_version': self.image.version,
            'image_size': total_size,
            'partition_count': len(self.image.partitions),
            'partitions': partition_info,
        }

    def replace_partition(
        self,
        name: str,
        data: bytes,
        memory_address: Optional[int] = None,
    ) -> None:
        """
        Replace a partition's data in the LK image.

        Args:
            name: Name of the partition to replace
            data: New partition data bytes
            memory_address: Optional memory address to set
        """
        if name not in self.image.partitions:
            raise KeyError(f"Partition '{name}' not found in image")

        partition = self.image.partitions[name]
        partition.data = data

        if memory_address is not None:
            partition.header.memory_address = memory_address

        self.image._rebuild_contents()
        self.logger.info(
            'Successfully replaced partition: %s (%d bytes)',
            name,
            len(data),
        )

    def cert_bypass(self, name: str, legacy: bool = False) -> None:
        """
        Apply cert bypass to partition NAME.

        The MTK preloader ASN.1 parser has a logic flaw:
          - bypass_mode=0 (new V6): only SEQUENCE (0x30) is parsed, other
            TLVs are scanned for OID+BITSTRING patterns. Prepending a 0xA0
            context-specific block with new hashes before the original DER
            causes the parser to pick up the injected hashes.
          - bypass_mode=1 (old V5/V6): any DER object is stepped
            into. Wrapping the original cert2 in a BIT_STRING (0x03) causes
            the parser to enter it, find the original SEQUENCE, and verify
            the signature. The injected hashes in the 0xA0 block are used
            for image verification.

        Args:
            name: Name of the partition to patch
            legacy: Use bypass_mode=1 (old V5/V6) with BIT_STRING wrapper
        """
        if name not in self.image.partitions:
            raise KeyError(f"Partition '{name}' not found in image")

        partition = self.image.partitions[name]

        cert2 = partition.cert2
        if not cert2:
            raise ValueError(
                f"Partition '{name}' does not have a cert2 certificate"
            )

        orig_der = cert2.data
        if not orig_der or orig_der[0] != 0x30:
            raise ValueError(
                f"cert2 for '{name}' does not start with SEQUENCE (0x30)"
            )

        image_hash, header_hash = self._compute_partition_hashes(partition)
        self.logger.info('Computed hashes for cert-bypass on %s:', name)
        self.logger.info('  Header hash: %s', header_hash.hex())
        self.logger.info('  Image hash:  %s', image_hash.hex())

        hash_block = self._build_hash_override_block(header_hash, image_hash)
        self.logger.info('  Hash override block: %d bytes', len(hash_block))

        if legacy:
            bit_string = self._wrap_in_bit_string(orig_der)
            self.logger.info(
                '  Legacy BIT_STRING wrapper: %d bytes', len(bit_string)
            )
            new_blob = bit_string + hash_block + orig_der
        else:
            new_blob = hash_block + orig_der

        cert2.data = new_blob
        self.image._rebuild_contents()
        self.logger.info(
            'Successfully applied cert-bypass to partition %s '
            '(mode=%s, new cert2 size: %d bytes)',
            name,
            'legacy' if legacy else 'v6',
            len(new_blob),
        )

    def cert_bypass_all(self, legacy: bool = False) -> List[str]:
        """
        Apply cert bypass to all partitions where cert2 hashes don't match
        the actual image data.

        Scans all partitions with cert2, computes current hashes, and
        compares them against the hashes stored in the cert2 DER.
        Applies bypass only to partitions with mismatched hashes.

        Args:
            legacy: Use bypass_mode=1 (old V5/V6) with BIT_STRING wrapper

        Returns:
            List of partition names that were patched
        """
        patched = []
        for name, partition in self.image.partitions.items():
            cert2 = partition.cert2
            if not cert2:
                continue

            orig_der = cert2.data
            if not orig_der or orig_der[0] != 0x30:
                self.logger.debug(
                    'Skipping %s: cert2 does not start with SEQUENCE', name
                )
                continue

            try:
                stored_img_hash, stored_hdr_hash = self._extract_hashes_from_der(
                    orig_der
                )
            except ValueError as e:
                self.logger.debug(
                    'Skipping %s: cannot extract hashes from cert2 (%s)',
                    name,
                    e,
                )
                continue

            current_img_hash, current_hdr_hash = self._compute_partition_hashes(
                partition
            )

            if (
                stored_img_hash == current_img_hash
                and stored_hdr_hash == current_hdr_hash
            ):
                self.logger.debug('Skipping %s: cert2 hashes match', name)
                continue

            self.logger.info(
                'Hash mismatch detected for %s — applying cert-bypass', name
            )
            self.cert_bypass(name, legacy=legacy)
            patched.append(name)

        return patched

    @staticmethod
    def _extract_hashes_from_der(der: bytes) -> Tuple[bytes, bytes]:
        """
        Extract image hash and header hash from a CERT2 DER blob.

        Searches for OID 2.16.886.2454.2.1 (image hash) and
        OID 2.16.886.2454.2.4 (header hash), then reads the
        following BIT STRING value.

        Returns:
            (image_hash, header_hash) tuple of 32-byte SHA-256 digests

        Raises:
            ValueError: If OIDs or BIT STRINGs are not found
        """
        oid_img_hash = '2.16.886.2454.2.1'
        oid_hdr_hash = '2.16.886.2454.2.4'

        def find_oid_hash(der_data: bytes, oid_str: str) -> bytes:
            oid_encoded = LkPatcher._encode_oid(oid_str)
            oid_tag = bytes([0x06, len(oid_encoded)]) + oid_encoded

            idx = der_data.find(oid_tag)
            if idx == -1:
                raise ValueError(f'OID {oid_str} not found')

            bs_off = idx + len(oid_tag)
            if bs_off + 34 > len(der_data):
                raise ValueError('Truncated BIT STRING after OID')
            if der_data[bs_off] != 0x03:
                raise ValueError(
                    f'Expected BIT STRING (0x03), got 0x{der_data[bs_off]:02x}'
                )
            bs_len = der_data[bs_off + 1]
            if bs_len != 0x21:
                raise ValueError(
                    f'Expected BIT STRING length 0x21, got 0x{bs_len:02x}'
                )
            if der_data[bs_off + 2] != 0x00:
                raise ValueError('BIT STRING has non-zero unused bits')
            return bytes(der_data[bs_off + 3 : bs_off + 35])

        img_hash = find_oid_hash(der, oid_img_hash)
        hdr_hash = find_oid_hash(der, oid_hdr_hash)
        return img_hash, hdr_hash

    @staticmethod
    def _encode_der_length(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        s = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(s)]) + s

    @staticmethod
    def _encode_oid(oid: str) -> bytes:
        parts = [int(x) for x in oid.split('.')]
        first = 40 * parts[0] + parts[1]
        out = bytearray([first])
        for p in parts[2:]:
            if p == 0:
                out.append(0)
                continue
            parts_b = []
            while p > 0:
                parts_b.insert(0, p & 0x7F)
                p >>= 7
            for i, v in enumerate(parts_b):
                if i != len(parts_b) - 1:
                    out.append(0x80 | v)
                else:
                    out.append(v)
        return bytes(out)

    @staticmethod
    def _build_oid_tlv(oid: str) -> bytes:
        b = LkPatcher._encode_oid(oid)
        return b'\x06' + LkPatcher._encode_der_length(len(b)) + b

    @staticmethod
    def _build_bitstring_tlv(payload: bytes) -> bytes:
        val = b'\x00' + payload
        return b'\x03' + LkPatcher._encode_der_length(len(val)) + val

    @staticmethod
    def _build_hash_override_block(header_hash: bytes, image_hash: bytes) -> bytes:
        oid_img_hdr_hash = '2.16.886.2454.2.4'
        oid_img_hash = '2.16.886.2454.2.1'

        parts = []
        parts.append(LkPatcher._build_oid_tlv(oid_img_hdr_hash))
        parts.append(LkPatcher._build_bitstring_tlv(header_hash))
        parts.append(LkPatcher._build_oid_tlv(oid_img_hash))
        parts.append(LkPatcher._build_bitstring_tlv(image_hash))

        content = b''.join(parts)
        return b'\xa0' + LkPatcher._encode_der_length(len(content)) + content

    @staticmethod
    def _wrap_in_bit_string(asn1_data: bytes) -> bytes:
        payload_len = len(asn1_data) + 1
        if payload_len > 0xFFFF:
            raise ValueError(
                'ASN.1 payload too large for a two-byte-length BIT STRING'
            )
        return (
            bytes([0x03, 0x82])
            + struct.pack('>H', payload_len)
            + b'\x00'
            + asn1_data
        )

    def _compute_partition_hashes(self, partition: LkPartition) -> Tuple[bytes, bytes]:
        """
        Compute image hash and header hash for a partition.
        """
        header_bytes = bytes(partition.header)
        data_bytes = bytes(partition.data)

        alignment = (
            partition.header.alignment if partition.header.is_extended else 8
        )
        if alignment and len(data_bytes) % alignment:
            padding_size = alignment - (len(data_bytes) % alignment)
        else:
            padding_size = 0

        full_part_bytes = header_bytes + data_bytes + b'\x00' * padding_size

        header_hash = sha256(full_part_bytes[:512]).digest()
        image_hash = sha256(full_part_bytes[512:]).digest()

        return image_hash, header_hash
