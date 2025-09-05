# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['website_security_tool.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('project_info.html', '.'),
        ('logo.png', '.'),
        ('requirements.txt', '.'),
    ],
    hiddenimports=[
        'tkinter',
        'tkinter.messagebox',
        'tkinter.filedialog',
        'tkinter.ttk',
        'tkinter.scrolledtext',
        'requests',
        'json',
        'threading',
        'hashlib',
        'base64',
        'socket',
        'webbrowser',
        'platform',
        're',
        'time',
        'os',
        'subprocess',
        'datetime',
        'urllib.parse',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='WebsiteSecurityTool',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='logo.png',
)
