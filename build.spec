# build.spec
block_cipher = None

a = Analysis(
    ['cursach.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('images/*', 'images'),
        ('icons/*', 'icons')
    ],
    datas=[
        (os.path.join(sys._MEIPASS, 'PyQt5', 'Qt5', 'plugins'), 'plugins'),
    ],
    hiddenimports=[
        'cryptography.hazmat.backends',
        'cryptography.hazmat.primitives',
        'argon2'
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
    name='WorkshopOfSecrets',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Запуск без консоли
    icon='icons/app_icon.ico',
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)