"""Review 2 pipeline: quantifying behavioral visibility loss due to malware packing.

The package processes capability *reports* (capa JSON, sandbox label lists,
recovery records) produced elsewhere. It never unpacks, decrypts, downloads or
executes any file, and it never launches capa, CAPE or a sandbox.
"""

__version__ = "0.2.0"
