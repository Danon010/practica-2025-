# API Specification

## Аутентификация
- `POST /auth/login` - Вход в систему
- `POST /auth/register` - Регистрация
- `GET /auth/me` - Получить текущего пользователя

## Сканирования
- `GET /scans/` - Список сканирований
- `POST /scans/` - Создать сканирование
- `GET /scans/{scan_id}` - Детали сканирования
- `DELETE /scans/{scan_id}` - Удалить сканирование
- `GET /scans/{scan_id}/results` - Результаты сканирования

## Уязвимости
- `GET /vulnerabilities/` - Список уязвимостей
- `GET /vulnerabilities/{vuln_id}` - Детали уязвимости
- `PUT /vulnerabilities/{vuln_id}` - Обновить статус

## Дашборд
- `GET /dashboard/stats` - Статистика для дашборда
- `GET /dashboard/activity` - Последняя активность
