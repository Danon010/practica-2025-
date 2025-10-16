from fastapi import HTTPException, status

class ScanAlreadyRunningError(Exception):
    """Сканирование уже выполняется"""
    pass

class InvalidTargetError(Exception):
    """Некорректная цель сканирования"""
    pass

class ScanLimitExceededError(Exception):
    """Превышен лимит сканирований"""
    pass

class ScannerError(Exception):
    """Ошибка сканера"""
    pass

class ScannerTimeoutError(Exception):
    """Таймаут сканирования"""
    pass

class ScannerNotReadyError(Exception):
    """Сканер не готов"""
    pass

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

inactive_user_exception = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="Inactive user",
)

admin_required_exception = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="Admin privileges required",
)
