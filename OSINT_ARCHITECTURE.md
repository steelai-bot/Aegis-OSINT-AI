# Цел

Изграждане на мултифункционален OSINT framework за проследяване на изтичане на данни (Dark Web, Data Brokers, Clear Web), с бърз и модерен интерфейс (подобен на Serus.ai). 

## User Review Required

> [!IMPORTANT]  
> Одобряваш ли избрания технологичен стек (React + Vite + Tailwind за frontend, Python FastAPI за backend)? 

## Open Questions

> [!WARNING]  
> 1. Желаеш ли реална интеграция с OSINT инструменти (напр. HaveIBeenPwned API, holehe) или да изградя базова структура (скелет) с mock данни, която да разширяваш впоследствие?
> 2. Да включвам ли база данни (SQLite/PostgreSQL) за запазване на резултатите от сканиранията?

## Proposed Changes

### Frontend (React + Vite + Tailwind CSS)

Изграждане на модерен, тъмен (dark mode) Dashboard с плавни анимации.

#### [NEW] `frontend/package.json`
Дефиниране на зависимости: React, Tailwind CSS, Lucide-react (за икони), React Router, Framer Motion (за анимации).

#### [NEW] `frontend/src/App.jsx`
Основен рутер и layout (Sidebar + Main Content).

#### [NEW] `frontend/src/pages/Dashboard.jsx`
Компонент за изобразяване на Health Score, Active Exposures и Alerts.

#### [NEW] `frontend/src/pages/Intelligence.jsx`
Търсачка за OSINT (по имейл, телефон, потребителско име).

### Backend (Python FastAPI)

Бърз и лек backend за изпълнение на OSINT сканиранията.

#### [NEW] `backend/requirements.txt`
Зависимости: fastapi, uvicorn, requests, aiohttp (за асинхронно сканиране).

#### [NEW] `backend/main.py`
FastAPI приложение с REST endpoints (`/api/scan/darkweb`, `/api/scan/databrokers`).

#### [NEW] `backend/osint_engine/scanner.py`
Ядрото за OSINT сканиране. Модули за проверка на имейли и телефони в публични бази.

## Verification Plan

### Manual Verification
1. Стартиране на backend сървъра (`uvicorn main:app`).
2. Стартиране на frontend сървъра (`npm run dev`).
3. Визуална инспекция на UI компонентите и изпълнение на тестово сканиране през браузъра.
