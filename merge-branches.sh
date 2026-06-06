#!/bin/bash

# Скрипт за автоматично сливане на всички codex/* клонове в main
# Използване: bash merge-branches.sh [--strategy ours|theirs|manual]
# --strategy ours: Запази версията от main при конфликти
# --strategy theirs: Приемо версията от клона (default)
# --strategy manual: Интерактивно питане при всеки конфликт

set -e

# Цветове за изход
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Параметри
STRATEGY="${1:---strategy theirs}"
STRATEGY_TYPE="theirs" # default

if [[ "$STRATEGY" == "--strategy" && ! -z "$2" ]]; then
    STRATEGY_TYPE="$2"
elif [[ "$STRATEGY" == *"ours"* ]]; then
    STRATEGY_TYPE="ours"
elif [[ "$STRATEGY" == *"theirs"* ]]; then
    STRATEGY_TYPE="theirs"
elif [[ "$STRATEGY" == *"manual"* ]]; then
    STRATEGY_TYPE="manual"
fi

# Функции за отпечатване
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_section() {
    echo -e "${MAGENTA}════════════════════════════════════════${NC}"
    echo -e "${MAGENTA}$1${NC}"
    echo -e "${MAGENTA}════════════════════════════════════════${NC}"
}

# Функция за разрешаване на конфликти
resolve_conflicts() {
    local branch=$1
    local strategy=$2
    
    print_info "Файлове с конфликти:"
    git diff --name-only --diff-filter=U
    
    if [ "$strategy" == "ours" ]; then
        print_info "Използване на версията от 'main'..."
        git diff --name-only --diff-filter=U | while read file; do
            git checkout --ours "$file"
            git add "$file"
        done
    elif [ "$strategy" == "theirs" ]; then
        print_info "Използване на версията от '$branch'..."
        git diff --name-only --diff-filter=U | while read file; do
            git checkout --theirs "$file"
            git add "$file"
        done
    elif [ "$strategy" == "manual" ]; then
        print_warning "Интерактивно разрешаване на конфликти за: $branch"
        git diff --name-only --diff-filter=U | while read file; do
            echo ""
            echo -e "${YELLOW}Конфликт в: $file${NC}"
            echo "1) Запази версията от 'main' (--ours)"
            echo "2) Запази версията от '$branch' (--theirs)"
            echo "3) Отвори в редактор"
            read -p "Избор (1/2/3): " choice
            
            case $choice in
                1)
                    git checkout --ours "$file"
                    git add "$file"
                    print_success "Запазена версията от 'main'"
                    ;;
                2)
                    git checkout --theirs "$file"
                    git add "$file"
                    print_success "Запазена версията от '$branch'"
                    ;;
                3)
                    ${EDITOR:-nano} "$file"
                    git add "$file"
                    print_success "Файлът е редактиран и добавен"
                    ;;
                *)
                    print_warning "Невалиден избор, използване на --theirs"
                    git checkout --theirs "$file"
                    git add "$file"
                    ;;
            esac
        done
    fi
}

# Проверки
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    print_error "Не си в Git хранилище!"
    exit 1
fi

print_section "НАЧАЛО НА СЛИВАНЕ"
print_info "Текущо хранилище: $(git rev-parse --show-toplevel)"
print_info "Стратегия за конфликти: $STRATEGY_TYPE"

# Проверка за main клон
if ! git rev-parse --verify main > /dev/null 2>&1; then
    print_error "Клонът 'main' не съществува!"
    exit 1
fi

# Проверка за незаписани промени
if ! git diff-index --quiet HEAD --; then
    print_error "Има незаписани промени! Моля, commit или stash тях преди да продължиш."
    git status
    exit 1
fi

# Преход към main
print_info "Преход към клона 'main'..."
git checkout main
print_success "Преход към 'main' успешен"

# Обновяване на main от remote
print_info "Обновяване на 'main' от remote..."
git fetch origin main
git reset --hard origin/main
print_success "main е актуален"

# Масив от всички клонове
BRANCHES=(
    "codex/agent-persistence"
    "codex/api-integration-tests"
    "codex/docker-docs-stack"
    "codex/event-agent-workflow"
    "codex/finding-correlation-graph"
    "codex/frontend-nextjs-dashboard"
    "codex/html-report-renderer"
    "codex/huggingface-report-renderers"
    "codex/kali-compatibility-tools"
    "codex/pdf-report-renderer"
    "codex/phase0-guardrails"
    "codex/plugin-configuration-tests"
    "codex/refactor-aegis-osint-architecture"
    "codex/report-templates"
)

# Броячи
MERGED=0
FAILED=0
SKIPPED=0
TOTAL=${#BRANCHES[@]}

print_section "СЛИВАНЕ НА КЛОНОВЕ ($TOTAL бр.)"

# Сливане на клонове
for i in "${!BRANCHES[@]}"; do
    branch=${BRANCHES[$i]}
    index=$((i + 1))
    
    echo ""
    print_info "[$index/$TOTAL] Обработка на: $branch"
    
    # Fetch клона ако не съществува локално
    if ! git rev-parse --verify "$branch" > /dev/null 2>&1; then
        print_info "Зареждане от remote..."
        if git fetch origin "$branch" 2>/dev/null; then
            git branch -t "$branch" origin/"$branch" 2>/dev/null || true
        else
            print_error "Не успя да се зареди '$branch'"
            ((SKIPPED++))
            continue
        fi
    fi
    
    # Опит за сливане
    if git merge --no-edit -X theirs "$branch" 2>/dev/null; then
        print_success "Слят успешно"
        ((MERGED++))
    else
        print_warning "Конфликт при сливане"
        
        # Разрешаване на конфликти
        resolve_conflicts "$branch" "$STRATEGY_TYPE"
        
        # Завършване на сливане
        if git commit --no-edit 2>/dev/null; then
            print_success "Конфликти разрешени и слят"
            ((MERGED++))
        else
            print_error "Неуспешно разрешаване"
            git merge --abort 2>/dev/null || true
            ((FAILED++))
        fi
    fi
done

print_section "ПУБЛИКУВАНЕ НА ПРОМЕНИТЕ"

# Push на промените
print_info "Публикуване в remote..."
if git push origin main --force-with-lease; then
    print_success "Промените са публикувани"
else
    print_warning "Push неуспешен"
fi

# Резюме
echo ""
print_section "РЕЗЮМЕ НА СЛИВАНЕТО"
echo ""
print_success "Успешно слети: $MERGED/$TOTAL"
if [ $FAILED -gt 0 ]; then
    print_error "Неуспешни: $FAILED"
fi
if [ $SKIPPED -gt 0 ]; then
    print_warning "Прескочени: $SKIPPED"
fi
echo ""

# Опционално: изтриване на клонове
echo ""
read -p "Искаш ли да изтриеш локалните codex/* клонове? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "Изтриване на локалните клонове..."
    for branch in "${BRANCHES[@]}"; do
        if git rev-parse --verify "$branch" > /dev/null 2>&1; then
            git branch -d "$branch" 2>/dev/null && print_success "✓ $branch" || print_warning "✗ $branch"
        fi
    done
    
    echo ""
    read -p "Искаш ли да изтриеш отдалечените клонове от GitHub? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Изтриване на отдалечени клонове..."
        for branch in "${BRANCHES[@]}"; do
            git push origin --delete "$branch" 2>/dev/null && print_success "✓ $branch" || print_warning "✗ $branch"
        done
    fi
fi

print_success "✨ Процесът е завършен!"
