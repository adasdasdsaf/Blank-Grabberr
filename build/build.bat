@echo off
cd ..
pyinstaller --noconfirm --onefile --windowed --icon "%cd%/build/imageres_15.ico" --upx-dir "%cd%/UPX" --version-file "%cd%/Blank Grabber/Components/version.txt" --uac-admin --add-data "%cd%/Blank Grabber/Components/rar.exe;." --add-data "%cd%/Blank Grabber/Components/rarreg.key;."  "%cd%/argcode.py"
