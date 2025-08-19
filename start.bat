@echo off
setlocal
title OnePush v1.2.1
where python >nul 2>nul || (echo [!] Python не найден. Поставь 3.11+ и перезапусти. & start https://www.python.org/downloads/ & pause & exit /b 1)
python -m pip install --upgrade pip
pip install -r requirements.txt || (echo [x] deps fail & pause & exit /b 1)
python onepush.py
