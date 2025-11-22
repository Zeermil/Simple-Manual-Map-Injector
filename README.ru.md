# Simple Manual Map Injector - Инструкция на Русском

Эта библиотека позволяет инжектировать DLL в процессы через Python, используя байты DLL из памяти (без необходимости сохранять файл на диск).

## Возможности

- **Универсальная компиляция** - одна команда создаёт версии для x86 и x64
- **Умный запускатель** - автоматически определяет архитектуру целевого процесса
- Поддержка x86 и x64 архитектур (отдельные бинарники для каждой)
- Поддержка x64 исключений (SEH)
- Инжект DLL из памяти (байтами)
- Указание имени процесса для инжекта
- Вызов через Python с помощью ctypes

## Быстрый старт - Универсальная компиляция

Скомпилируйте версии для x86 и x64 одной командой:

```cmd
build-all.bat
```

Или через PowerShell:
```powershell
.\build-all.ps1
```

Это создаст все исполняемые файлы в папке `bin`, включая универсальный запускатель.

## Использование

### Универсальный запускатель (Рекомендуется)

Универсальный запускатель автоматически определяет архитектуру целевого процесса и использует правильный инжектор:

```cmd
UniversalInjector.exe mydll.dll notepad.exe
```

Не нужно беспокоиться, 32-битный или 64-битный notepad.exe - всё автоматически!

### Командная строка (Выбор архитектуры вручную)

Для ручного выбора архитектуры:
- `Injector-x64.exe dll_path process_name` - Для 64-битных процессов
- `Injector-x86.exe dll_path process_name` - Для 32-битных процессов

## Компиляция в DLL через CMake

### Требования

1. **CMake** (версия 3.15 или выше)
   - Скачать: https://cmake.org/download/

2. **Visual Studio** (2019 или выше)
   - Необходимый компонент: "Разработка классических приложений на C++"
   - Скачать: https://visualstudio.microsoft.com/ru/downloads/

3. **Windows SDK**
   - Обычно устанавливается вместе с Visual Studio

### Универсальная компиляция (Рекомендуется)

Скомпилируйте версии для x86 и x64 автоматически:

**Используя Batch-скрипт:**
```cmd
build-all.bat
```

**Используя PowerShell:**
```powershell
.\build-all.ps1
```

**Результат:** Все файлы в папке `bin`:
- `ManualMapInjector-x64.dll` и `ManualMapInjector-x86.dll`
- `Injector-x64.exe` и `Injector-x86.exe`
- `UniversalInjector.exe` (умный запускатель)

Подробные инструкции см. в [BUILD_UNIVERSAL.md](BUILD_UNIVERSAL.md).

### Ручная компиляция (Одна архитектура)

**Только для x64:**
```cmd
mkdir build-x64 && cd build-x64
cmake .. -G "Visual Studio 16 2019" -A x64
cmake --build . --config Release
```

**Только для x86:**
```cmd
mkdir build-x86 && cd build-x86
cmake .. -G "Visual Studio 16 2019" -A Win32
cmake --build . --config Release
```

## Использование с Python

### Пример кода

```python
import ctypes

# Загрузить DLL инжектора (используйте правильную архитектуру)
injector = ctypes.CDLL("ManualMapInjector-x64.dll")

# Прочитать DLL, которую нужно инжектировать (из памяти!)
with open("target.dll", "rb") as f:
    dll_bytes = f.read()

# Настроить сигнатуру функции
injector.InjectDllFromMemorySimple.argtypes = [
    ctypes.c_char_p,                    # имя процесса
    ctypes.POINTER(ctypes.c_ubyte),     # байты DLL
    ctypes.c_size_t                     # размер
]
injector.InjectDllFromMemorySimple.restype = ctypes.c_int

# Конвертировать в ctypes
dll_array = (ctypes.c_ubyte * len(dll_bytes)).from_buffer_copy(dll_bytes)
process_name = b"notepad.exe"  # имя процесса

# Выполнить инжект
result = injector.InjectDllFromMemorySimple(process_name, dll_array, len(dll_bytes))

# Проверить результат
if result == 0:
    print("✓ Инжект успешен!")
elif result == -1:
    print("✗ Ошибка: Процесс не найден")
elif result == -2:
    print("✗ Ошибка: Не удалось открыть процесс (нужны права администратора)")
elif result == -3:
    print("✗ Ошибка: Несовпадение архитектуры (используйте x86 или x64 DLL)")
elif result == -4:
    print("✗ Ошибка: Неверные данные DLL")
elif result == -5:
    print("✗ Ошибка: Инжект не удался")
```

### Готовый пример

Используйте готовый скрипт `example_python.py`:

```bash
python example_python.py target.dll notepad.exe
```

**Важно:** Архитектура Python и DLL должны совпадать:
- 64-битный Python → используйте `ManualMapInjector-x64.dll`
- 32-битный Python → используйте `ManualMapInjector-x86.dll`

## API

### InjectDllFromMemorySimple (Рекомендуется)

Простая функция с параметрами по умолчанию.

**Параметры:**
- `processName` (строка) - имя процесса, например "notepad.exe"
- `dllData` (байты) - байты DLL в памяти
- `dllSize` (число) - размер данных DLL

**Возвращаемые значения:**
- `0` - успех
- `-1` - процесс не найден
- `-2` - не удалось открыть процесс (проверьте права)
- `-3` - несовпадение архитектуры (x86 vs x64)
- `-4` - неверные данные DLL
- `-5` - инжект не удался

### InjectDllFromMemory (Расширенная версия)

Расширенная функция с настраиваемыми параметрами.

**Дополнительные параметры:**
- `clearHeader` (bool) - очистить PE заголовок после инжекта
- `clearNonNeededSections` (bool) - очистить ненужные секции
- `adjustProtections` (bool) - настроить защиту памяти
- `sehExceptionSupport` (bool) - поддержка SEH исключений для x64

## Преимущества

✅ **Инжект из памяти** - не нужно сохранять DLL на диск  
✅ **Простой API** - легко использовать из Python  
✅ **Безопасность** - автоматическая очистка памяти  
✅ **Гибкость** - настраиваемые параметры инжекта  
✅ **Кроссплатформенность** - работает с x86 и x64  

## Важные примечания

⚠️ Для инжекта в процессы нужны права администратора  
⚠️ Некоторые антивирусы могут блокировать инжектор  
⚠️ Используйте только для своих процессов или с разрешения  
⚠️ Архитектура инжектора, целевого процесса и DLL должны совпадать

## Дополнительная информация

Подробные инструкции по сборке смотрите в файле `BUILD.md`.

Полная документация на английском в файле `README.md`.
