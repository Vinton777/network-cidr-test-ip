#!/bin/bash

# Функция проверки наличия команды
check_cmd() {
    command -v "$1" >/dev/null 2>&1
}

MISSING=()

check_cmd python3 || MISSING+=("python3")
check_cmd whois || MISSING+=("whois")
check_cmd ping || MISSING+=("ping")
check_cmd tar || MISSING+=("tar")

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "Отсутствуют необходимые зависимости: ${MISSING[*]}"
    echo "Пожалуйста, запустите установочный скрипт для их инсталляции:"
    echo "curl -sSL https://raw.githubusercontent.com/Vinton777/network-cidr-test-ip/master/install.sh | bash"
    exit 1
fi

# Получаем директорию, где находится этот bash-скрипт
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PYTHON_SCRIPT="$SCRIPT_DIR/netblock_analyzer.py"

if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo "Ошибка: Не найден файл $PYTHON_SCRIPT"
    exit 1
fi

# Запуск Python скрипта в текущей директории пользователя
exec python3 "$PYTHON_SCRIPT" "$PWD"
