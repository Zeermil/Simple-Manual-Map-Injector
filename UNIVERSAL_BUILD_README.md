# Universal Build System - README

## English

### What is this?

This update makes the Manual Map Injector **universal** - you can now build and use it for both 32-bit and 64-bit applications with a single command.

### What's New?

1. **Universal Build Scripts**
   - `build-all.bat` - Windows batch script
   - `build-all.ps1` - PowerShell script
   - Both scripts automatically build x86 and x64 versions in one go

2. **Universal Launcher**
   - `UniversalInjector.exe` - Smart launcher that automatically detects whether the target process is 32-bit or 64-bit
   - No more guessing which injector to use!

3. **Organized Output**
   - All built files are placed in a single `bin` directory
   - Easy to find and use

### How to Use

#### Build Everything (One Command)
```cmd
build-all.bat
```

#### Use the Universal Launcher
```cmd
bin\UniversalInjector.exe mydll.dll notepad.exe
```

That's it! The launcher will:
1. Find the notepad.exe process
2. Detect if it's 32-bit or 64-bit
3. Launch the appropriate injector (`Injector-x86.exe` or `Injector-x64.exe`)
4. Inject your DLL

### Benefits

✅ **No more architecture confusion** - One launcher for all cases
✅ **Faster development** - Build both versions at once
✅ **Easy distribution** - Package the entire `bin` folder
✅ **User-friendly** - Users don't need to know the target architecture

---

## Русский

### Что это?

Это обновление делает Manual Map Injector **универсальным** - теперь можно собрать и использовать его для 32-битных и 64-битных приложений одной командой.

### Что нового?

1. **Универсальные скрипты сборки**
   - `build-all.bat` - Windows batch скрипт
   - `build-all.ps1` - PowerShell скрипт
   - Оба скрипта автоматически собирают версии x86 и x64 за один раз

2. **Универсальный запускатель**
   - `UniversalInjector.exe` - Умный запускатель, который автоматически определяет, 32-битный или 64-битный целевой процесс
   - Больше не нужно угадывать, какой инжектор использовать!

3. **Организованный вывод**
   - Все собранные файлы помещаются в одну папку `bin`
   - Легко найти и использовать

### Как использовать

#### Собрать всё (Одна команда)
```cmd
build-all.bat
```

#### Использовать универсальный запускатель
```cmd
bin\UniversalInjector.exe mydll.dll notepad.exe
```

Вот и всё! Запускатель:
1. Найдёт процесс notepad.exe
2. Определит, 32-битный он или 64-битный
3. Запустит соответствующий инжектор (`Injector-x86.exe` или `Injector-x64.exe`)
4. Инжектирует вашу DLL

### Преимущества

✅ **Больше никакой путаницы с архитектурой** - Один запускатель для всех случаев
✅ **Быстрая разработка** - Сборка обеих версий сразу
✅ **Простое распространение** - Упакуйте всю папку `bin`
✅ **Удобно для пользователей** - Пользователям не нужно знать архитектуру цели

---

## Technical Details / Технические детали

### Architecture Detection / Определение архитектуры

The universal launcher uses Windows API functions to detect process architecture:
- `IsWow64Process()` - Detects if a process is running under WoW64 (32-bit on 64-bit Windows)
- Automatically selects the correct injector based on the result

Универсальный запускатель использует функции Windows API для определения архитектуры процесса:
- `IsWow64Process()` - Определяет, запущен ли процесс под WoW64 (32-битный на 64-битной Windows)
- Автоматически выбирает правильный инжектор на основе результата

### Build Process / Процесс сборки

The build scripts perform the following steps:
1. Create separate build directories for x86 and x64
2. Configure CMake for each architecture
3. Build both versions
4. Copy all outputs to a single `bin` directory

Скрипты сборки выполняют следующие шаги:
1. Создают отдельные папки сборки для x86 и x64
2. Настраивают CMake для каждой архитектуры
3. Собирают обе версии
4. Копируют все результаты в одну папку `bin`

### Files Structure / Структура файлов

After building:
```
Simple-Manual-Map-Injector/
├── bin/                              # All final executables
│   ├── ManualMapInjector-x64.dll    # 64-bit injector DLL
│   ├── ManualMapInjector-x86.dll    # 32-bit injector DLL
│   ├── Injector-x64.exe             # 64-bit CLI injector
│   ├── Injector-x86.exe             # 32-bit CLI injector
│   └── UniversalInjector.exe        # Universal launcher
├── build-x64/                        # x64 build artifacts
├── build-x86/                        # x86 build artifacts
├── build-all.bat                     # Batch build script
├── build-all.ps1                     # PowerShell build script
└── ...
```

---

## Requirements / Требования

- CMake 3.15+
- Visual Studio 2019+ with C++ Desktop Development
- Windows SDK

---

## Support / Поддержка

For detailed instructions, see:
- [BUILD_UNIVERSAL.md](BUILD_UNIVERSAL.md) - Complete build guide
- [QUICKSTART.md](QUICKSTART.md) - Quick start guide
- [README.md](README.md) - Main documentation

Для подробных инструкций см.:
- [BUILD_UNIVERSAL.md](BUILD_UNIVERSAL.md) - Полное руководство по сборке
- [QUICKSTART.md](QUICKSTART.md) - Руководство быстрого старта
- [README.ru.md](README.ru.md) - Основная документация на русском
