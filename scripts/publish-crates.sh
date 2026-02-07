#!/bin/bash
# Publish all nklave crates to crates.io in dependency order
# Usage: ./scripts/publish-crates.sh [--dry-run]

set -e

DRY_RUN=""
ALLOW_DIRTY="--allow-dirty"
if [ "$1" == "--dry-run" ]; then
    DRY_RUN="--dry-run"
    echo "=== DRY RUN MODE ==="
fi

# Delay between publishes (crates.io rate limiting)
DELAY_SECONDS=45

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Crates in dependency order
CRATES=(
    "nklave-core"      # No internal deps
    "nklave-storage"   # Depends on: core
    "nklave-cosmos"    # Depends on: core
    "nklave-api"       # Depends on: core, storage
    "nklave-cli"       # Depends on: core, storage
    "nklave-server"    # Depends on: core, api, storage
)

build_ui() {
    echo -e "${BLUE}Building UI...${NC}"
    cd "$PROJECT_ROOT/ui"

    if command -v pnpm &> /dev/null; then
        pnpm install && pnpm build
    else
        npm install && npm run build
    fi

    echo -e "${BLUE}Copying UI to nklave-api crate...${NC}"
    rm -rf "$PROJECT_ROOT/crates/nklave-api/ui-dist"
    cp -r "$PROJECT_ROOT/ui/dist" "$PROJECT_ROOT/crates/nklave-api/ui-dist"

    cd "$PROJECT_ROOT"
    echo -e "${GREEN}UI built and copied successfully${NC}"
}

publish_crate() {
    local crate=$1
    echo -e "${YELLOW}Publishing $crate...${NC}"

    if cargo publish -p "$crate" $ALLOW_DIRTY $DRY_RUN; then
        echo -e "${GREEN}Successfully published $crate${NC}"
        return 0
    else
        echo -e "${RED}Failed to publish $crate${NC}"
        return 1
    fi
}

wait_for_index() {
    local crate=$1
    local seconds=$2

    if [ -n "$DRY_RUN" ]; then
        echo "Skipping wait (dry run)"
        return
    fi

    echo -e "${YELLOW}Waiting ${seconds}s for crates.io to index $crate...${NC}"

    for ((i=seconds; i>0; i--)); do
        printf "\r  %02d seconds remaining..." $i
        sleep 1
    done
    printf "\r  Done!                    \n"
}

echo "========================================"
echo "  Nklave Crates Publisher"
echo "========================================"
echo ""
echo "Publishing order:"
for i in "${!CRATES[@]}"; do
    echo "  $((i+1)). ${CRATES[$i]}"
done
echo ""

# Build UI first
build_ui
echo ""

# Confirm before publishing
if [ -z "$DRY_RUN" ]; then
    echo -e "${YELLOW}This will publish ${#CRATES[@]} crates to crates.io.${NC}"
    read -p "Continue? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

echo ""
echo "Starting publication..."
echo ""

for i in "${!CRATES[@]}"; do
    crate="${CRATES[$i]}"

    echo "========================================"
    echo "[$((i+1))/${#CRATES[@]}] $crate"
    echo "========================================"

    if ! publish_crate "$crate"; then
        echo -e "${RED}Publication failed. Stopping.${NC}"
        exit 1
    fi

    # Wait between publishes (except for last one)
    if [ $i -lt $((${#CRATES[@]} - 1)) ]; then
        wait_for_index "$crate" $DELAY_SECONDS
    fi

    echo ""
done

echo "========================================"
echo -e "${GREEN}All crates published successfully!${NC}"
echo "========================================"
echo ""
echo "Verify at:"
for crate in "${CRATES[@]}"; do
    echo "  https://crates.io/crates/$crate"
done
