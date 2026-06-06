#!/bin/bash

# Скрипт за автоматично сливане на всички codex/* клонове в main
# Използване: bash merge-branches.sh

set -e

# Цветове за изход
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функция за отпечатване на информация
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

# Масив от всички клонове за сливане
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

# Проверка дали сме в Git хранилище
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    print_error "Не си в Git хранилище!"
    exit 1
fi

print_info "Начало на процеса на сливане..."
print_info "Текущо хранилище: $(git rev-parse --show-toplevel)"

# Проверка дали main клонът съществува
if ! git rev-parse --verify main > /dev/null 2>&1; then
    print_error "Клонът 'main' не съществува!"
    exit 1
fi

# Преведи се на main
print_info "Преход към клона 'main'..."
git checkout main
if [ $? -eq 0 ]; then
    print_success "Преход към 'main' успешен"
else
    print_error "Неуспешен преход към 'main'"
    exit 1
fi

# Обновяване на main от remote
print_info "Обновяване на 'main' от remote..."
git pull origin main --ff-only 2>/dev/null || print_warning "Не можа да се обновя от remote (може да няма интернет)"

# Броячи
MERGED=0
FAILED=0
SKIPPED=0

# Сливане на всички клонове
for branch in "${BRANCHES[@]}"; do
    print_info "Обработка на клон: $branch"
    
    # Проверка дали клонът съществува локално
    if ! git rev-parse --verify "$branch" > /dev/null 2>&1; then
        print_warning "Клонът '$branch' не съществува локално. Зареждане от remote..."
        git fetch origin "$branch" 2>/dev/null || {
            print_error "Не можа да се зареди '$branch' от remote"
            ((SKIPPED++))
            continue
        }
    fi
    
    # Опит за сливане
    if git merge --no-edit "$branch" 2>/dev/null; then
        print_success "Клонът '$branch' е слят успешно"
        ((MERGED++))
    else
        print_warning "Конфликт при сливане на '$branch'"
        
        # Опит за автоматично разрешаване на конфликти
        print_info "Опит за автоматично разрешаване на конфликти..."
        
        # Вземи версията от клона (их версия)
        git diff --name-only --diff-filter=U | while read file; do
            git checkout --theirs "$file"
            git add "$file"
        done
        
        # Довършване на сливане
        if git commit --no-edit 2>/dev/null; then
            print_success "Конфликтите са разрешени. Клонът '$branch' е слят"
            ((MERGED++))
        else
            print_error "Неуспешно разрешаване на конфликтите за '$branch'"
            git merge --abort 2>/dev/null || true
            ((FAILED++))
        fi
    fi
done

# Публикуване на промените
print_info "Публикуване на промените в remote..."
if git push origin main; then
    print_success "Промените са публикувани в remote"
else
    print_warning "Не можа да се публикува (провери интернет връзката)"
fi

# Резюме
echo ""
print_info "╔════════════════════════════════════════╗"
print_info "║        РЕЗЮМЕ НА СЛИВАНЕТО             ║"
print_info "╠════════════════════════════════════════╣"
print_success "║ Успешно слети: $MERGED"
print_error "║ Неуспешни: $FAILED"
print_warning "║ Прескочени: $SKIPPED"
print_info "╚════════════════════════════════════════╝"

# Опционално: изтриване на клонове след успешно сливане
print_info ""
read -p "Искаш ли да изтриеш локалните codex/* клонове? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "Изтриване на локалните клонове..."
    for branch in "${BRANCHES[@]}"; do
        if git rev-parse --verify "$branch" > /dev/null 2>&1; then
            git branch -d "$branch" 2>/dev/null && print_success "Изтрит: $branch" || print_warning "Не можа да се изтрие: $branch"
        fi
    done
    
    read -p "Искаш ли да изтриеш отдалечените клонове от GitHub? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Изтриване на отдалечени клонове..."
        for branch in "${BRANCHES[@]}"; do
            git push origin --delete "$branch" 2>/dev/null && print_success "Изтрит от remote: $branch" || print_warning "Не можа да се изтрие от remote: $branch"
        done
    fi
fi

print_success "Процесът е завършен!"
