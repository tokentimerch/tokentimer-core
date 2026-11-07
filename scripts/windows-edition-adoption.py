"""Produce one provisional edition adoption record from the actual archive bytes.

The caller must supply independently authenticated candidate metadata and capture
what the edition really consumed through a trusted capture. Only the archive
digest and equality of the supplied bytes are checked; other digests, commits,
version and architecture are caller claims. This check neither authenticates
the caller nor proves installation, and its output cannot authorize a release.
"""
import hashlib
import json
import re

MAX_ARCHIVE = 128 * 1024 * 1024
ROLES = frozenset(('archive', 'checksum', 'signature', 'sbom', 'inventory', 'launcher'))
DIGEST = re.compile(r'[a-f0-9]{64}\Z')
COMMIT = re.compile(r'[a-f0-9]{40}\Z')


def produce(metadata, staged, consumed):
    fields = {'sourceCommit', 'version', 'architecture', 'artifactDigests', 'editionCommit', 'editionCoreCommit'}
    if not isinstance(metadata, dict) or set(metadata) != fields:
        raise ValueError('Invalid candidate metadata')
    if any(not isinstance(metadata[k], str) or not COMMIT.fullmatch(metadata[k]) for k in ('sourceCommit', 'editionCommit', 'editionCoreCommit')):
        raise ValueError('Invalid commit')
    if metadata['sourceCommit'] != metadata['editionCoreCommit']:
        raise ValueError('Edition core pin mismatch')
    if metadata['architecture'] not in ('amd64', 'arm64') or not isinstance(metadata['version'], str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', metadata['version']):
        raise ValueError('Invalid candidate identity')
    digests = metadata['artifactDigests']
    if not isinstance(digests, dict) or set(digests) != ROLES or any(not isinstance(v, str) or not DIGEST.fullmatch(v) for v in digests.values()):
        raise ValueError('Invalid artifact digests')
    if not isinstance(staged, bytes) or not isinstance(consumed, bytes) or not 0 < len(staged) <= MAX_ARCHIVE or not 0 < len(consumed) <= MAX_ARCHIVE:
        raise ValueError('Invalid candidate archive bytes')
    if staged != consumed or hashlib.sha256(staged).hexdigest() != digests['archive']:
        raise ValueError('Edition did not consume the candidate archive')
    record = {'caseId': 'same-candidate-bytes', 'status': 'passed', **metadata}
    return json.dumps(record, sort_keys=True, separators=(',', ':')).encode('utf-8')
