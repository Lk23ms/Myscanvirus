@echo off
cd /d "%~dp0"
python -m pip install -r requirements.txt pyinstaller -q
rem --uac-admin: exe tu xin quyen Admin (de disable/delete startup duoc)
pyinstaller --onefile --name OnlySnStudio --uac-admin --add-data "templates;templates" app.py
echo.
echo Xong! File exe nam o: dist\OnlySnStudio.exe
pause
