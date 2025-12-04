# Simple Manual Map Injector - Инструкция на Русском

Эта библиотека позволяет инжектировать DLL в процессы через Python, используя байты DLL из памяти (без необходимости сохранять файл на диск).

## Возможности

- **Кросс-архитектурная поддержка**: 64-битный инжектор может инжектить как в 32-битные, так и в 64-битные процессы
- Поддержка x86 и x64 архитектур
- Поддержка x64 исключений (SEH)
- **Защита от отладки (Anti-Debug)**: Обнаружение отладчика и предотвращение инжекта при отладке
- **Защита от дампа (Anti-Dump)**: Очистка флага BeingDebugged в PEB для скрытия от отладчиков
- **Поддержка шифрования DLL**: Инжект зашифрованных DLL с автоматической расшифровкой
- Инжект DLL из памяти (байтами)
- Указание имени процесса для инжекта
- Вызов через Python с помощью ctypes

## Компиляция в DLL через CMake

### Требования

1. **CMake** (версия 3.15 или выше)
   - Скачать: https://cmake.org/download/

2. **Visual Studio** (2019 или выше)
   - Необходимый компонент: "Разработка классических приложений на C++"
   - Скачать: https://visualstudio.microsoft.com/ru/downloads/

3. **Windows SDK**
   - Обычно устанавливается вместе с Visual Studio

### Быстрая сборка - Все архитектуры (Рекомендуется)

Чтобы собрать обе версии (x86 и x64) за один раз, используйте скрипт сборки:

```cmd
build_all.bat
```

Это создаст:
- `build/Injector-x64.exe` - 64-битный инжектор (может инжектить в 32-битные и 64-битные процессы)
- `build/Injector-x86.exe` - 32-битный помощник (автоматически используется x64 инжектором)
- `build/ManualMapInjector-x64.dll` - 64-битная DLL для Python
- `build/ManualMapInjector-x86.dll` - 32-битная DLL для Python

**Важно:** Держите оба файла `Injector-x64.exe` и `Injector-x86.exe` в одной папке. 64-битный инжектор автоматически использует 32-битный помощник при инжекте в 32-битные процессы.

### Ручная сборка - Одна архитектура

#### Шаги компиляции x64:

1. **Откройте "Developer Command Prompt for VS 2019"**
   - Пуск → Visual Studio 2019 → Developer Command Prompt

2. **Перейдите в папку проекта:**
   ```cmd
   cd путь\к\Simple-Manual-Map-Injector
   ```

3. **Создайте папку для сборки:**
   ```cmd
   mkdir build
   cd build
   ```

4. **Настройте CMake для x64:**
   ```cmd
   cmake .. -G "Visual Studio 16 2019" -A x64
   ```

5. **Скомпилируйте проект:**
   ```cmd
   cmake --build . --config Release
   ```

#### Шаги компиляции x86:

Аналогично x64, но используйте:
```cmd
cmake .. -G "Visual Studio 16 2019" -A Win32
```

6. **Найдите результат в папке `build/Release/`:**
   - `ManualMapInjector-x64.dll` (или x86 версия) - для использования с Python
   - `Injector-x64.exe` (или x86 версия) - консольная утилита

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

### Инжект с шифрованием DLL

```python
import ctypes

# Функция шифрования (XOR шифр)
def xor_encrypt(data, key):
    key_bytes = key.encode('utf-8')
    return bytes([data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data))])

# Загрузить DLL инжектора
injector = ctypes.CDLL("ManualMapInjector-x64.dll")

# Прочитать и зашифровать DLL
with open("target.dll", "rb") as f:
    dll_bytes = f.read()

encryption_key = "МойСекретныйКлюч123"
encrypted_dll = xor_encrypt(dll_bytes, encryption_key)

# Настроить сигнатуру функции
injector.InjectEncryptedDllFromMemorySimple.argtypes = [
    ctypes.c_char_p,                    # имя процесса
    ctypes.POINTER(ctypes.c_ubyte),     # зашифрованные байты DLL
    ctypes.c_size_t,                    # размер DLL
    ctypes.POINTER(ctypes.c_ubyte),     # ключ шифрования
    ctypes.c_size_t                     # размер ключа
]
injector.InjectEncryptedDllFromMemorySimple.restype = ctypes.c_int

# Конвертировать в ctypes
dll_array = (ctypes.c_ubyte * len(encrypted_dll)).from_buffer_copy(encrypted_dll)
key_array = (ctypes.c_ubyte * len(encryption_key)).from_buffer_copy(encryption_key.encode('utf-8'))
process_name = b"notepad.exe"

# Выполнить инжект зашифрованной DLL
result = injector.InjectEncryptedDllFromMemorySimple(
    process_name, dll_array, len(encrypted_dll), 
    key_array, len(encryption_key)
)
print(f"Результат: {result}")  # 0 = успех
```

Используйте готовый скрипт `example_encrypted_python.py`:

```bash
python example_encrypted_python.py target.dll notepad.exe МойКлюч123
```

## Утилиты шифрования

### Скрипт шифрования DLL

Используйте `dll_encryptor.py` для шифрования/дешифрования DLL файлов:

```bash
# Сгенерировать случайный ключ шифрования
python dll_encryptor.py genkey

# Зашифровать DLL
python dll_encryptor.py encrypt input.dll output.dll.enc МойКлюч123

# Расшифровать DLL
python dll_encryptor.py decrypt input.dll.enc output.dll МойКлюч123
```

## Функции безопасности

### Защита от отладки (Anti-Debug)

Инжектор включает несколько проверок на наличие отладчика:
- `IsDebuggerPresent()` - базовое обнаружение отладчика
- `CheckRemoteDebuggerPresent()` - обнаружение удалённого отладчика
- `NtQueryInformationProcess()` - продвинутое обнаружение через NT API
- Проверка флага BeingDebugged в PEB

Если обнаружен отладчик, инжект будет прерван для предотвращения анализа.

### Защита от дампа (Anti-Dump)

Инжектор реализует техники защиты от дампа:
- Очистка флага BeingDebugged в PEB в целевом процессе
- Удаление PE заголовков после инжекта (настраивается)
- Очистка несущественных секций (настраивается)

### Шифрование DLL

DLL могут быть зашифрованы перед инжектом:
- Использует XOR шифр для шифрования/дешифрования
- Расшифровка происходит в памяти перед инжектом
- Зашифрованные DLL сложнее обнаружить и анализировать
- Включены примеры на Python для процесса шифрования

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

### InjectEncryptedDllFromMemorySimple (Инжект с шифрованием)

Простая функция для инжекта зашифрованных DLL с параметрами по умолчанию.

**Параметры:**
- `processName` (строка) - имя процесса, например "notepad.exe"
- `encryptedDllData` (байты) - зашифрованные байты DLL в памяти
- `dllSize` (число) - размер зашифрованных данных DLL
- `encryptionKey` (байты) - ключ шифрования в байтах
- `keySize` (число) - размер ключа шифрования

**Возвращаемые значения:**
- `0` - успех
- `-1` - процесс не найден
- `-2` - не удалось открыть процесс (проверьте права)
- `-3` - несовпадение архитектуры (x86 vs x64)
- `-4` - неверные данные DLL или ключ шифрования
- `-5` - инжект не удался
- `-6` - расшифровка не удалась

### InjectEncryptedDllFromMemory (Расширенный инжект с шифрованием)

Расширенная функция для инжекта зашифрованных DLL с настраиваемыми параметрами.

**Дополнительные параметры:** Такие же как в `InjectDllFromMemory`

**Примечание:** Инжектор использует XOR шифр для шифрования/дешифрования. Один и тот же ключ должен использоваться для шифрования (в Python) и дешифрования (в инжекторе).

## Преимущества

✅ **Инжект из памяти** - не нужно сохранять DLL на диск  
✅ **Простой API** - легко использовать из Python  
✅ **Безопасность** - автоматическая очистка памяти  
✅ **Защита от отладки** - обнаружение и предотвращение отладки  
✅ **Защита от дампа** - скрытие от отладчиков в целевом процессе  
✅ **Шифрование DLL** - инжект зашифрованных DLL с расшифровкой в памяти  
✅ **Гибкость** - настраиваемые параметры инжекта  
✅ **Кроссплатформенность** - работает с x86 и x64  

## Важные примечания

⚠️ Для инжекта в процессы нужны права администратора  
⚠️ Некоторые антивирусы могут блокировать инжектор  
⚠️ Используйте только для своих процессов или с разрешения  
✅ 64-битный инжектор (`Injector-x64.exe`) может инжектить как в 32-битные, так и в 64-битные процессы  
✅ Для кросс-архитектурного инжекта держите оба EXE файла (x64 и x86) в одной папке

## Дополнительная информация

Подробные инструкции по сборке смотрите в файле `BUILD.md`.

Полная документация на английском в файле `README.md`.
