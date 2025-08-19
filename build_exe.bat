@echo off
setlocal
title Build OnePush.exe
where python >nul 2>nul || (echo [!] Python не найден & pause & exit /b 1)
python -m pip install --upgrade pip
pip install --upgrade pyinstaller -r requirements.txt || (echo [x] deps fail & pause & exit /b 1)
pyinstaller --noconfirm --clean --windowed --onefile --name "OnePush" onepush.py
echo [✓] Готово: dist\OnePush.exe
pause
