#!/bin/bash
# =============================================================================
# BUILD ALL IMAGES - Upgraded Happiness V3.1 ETCD
# =============================================================================
# Script completo para destruir y reconstruir todas las imágenes Docker
# Autor: Sistema Upgraded Happiness
# Versión: V3.1 ETCD Integration
# =============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="upgraded-happiness"
VERSION_TAG="v3.1-etcd"
BUILD_DATE=$(date +"%Y%m%d_%H%M%S")

echo -e "${CYAN}===============================================================================${NC}"
echo -e "${CYAN} 🚀 UPGRADED HAPPINESS V3.1 ETCD - BUILD ALL IMAGES${NC}"
echo -e "${CYAN}===============================================================================${NC}"
echo -e "${BLUE}📅 Build Date: ${BUILD_DATE}${NC}"
echo -e "${BLUE}🏗️  Project: ${PROJECT_NAME}${NC}"
echo -e "${BLUE}🏷️  Version: ${VERSION_TAG}${NC}"
echo -e "${CYAN}===============================================================================${NC}"

# =============================================================================
# STEP 1: CLEANUP PREVIOUS IMAGES
# =============================================================================

echo -e "\n${YELLOW}🧹 STEP 1: CLEANING UP PREVIOUS IMAGES${NC}"
echo -e "${YELLOW}===============================================================================${NC}"

# Function to remove images safely
cleanup_images() {
    local component=$1
    echo -e "${YELLOW}🗑️  Removing ${component} images...${NC}"
    
    # Remove by tag patterns
    docker images | grep "${PROJECT_NAME}/${component}" | awk '{print $1":"$2}' | xargs -r docker rmi -f 2>/dev/null || true
    
    # Remove any dangling images related to this component
    docker images -f "dangling=true" -q | xargs -r docker rmi -f 2>/dev/null || true
    
    echo -e "${GREEN}   ✅ ${component} images cleaned${NC}"
}

# Components list
COMPONENTS=("sniffer" "geoip" "ml-detector" "scheduler" "simple-firewall-agent" "dashboard")

# Clean each component
for component in "${COMPONENTS[@]}"; do
    cleanup_images "$component"
done

# Additional cleanup - remove unused networks and volumes related to the project
echo -e "${YELLOW}🧹 Cleaning unused Docker resources...${NC}"
docker system prune -f --volumes 2>/dev/null || true
echo -e "${GREEN}   ✅ Docker system cleaned${NC}"

echo -e "${GREEN}🎉 CLEANUP COMPLETED${NC}"

# =============================================================================
# STEP 2: BUILD ALL IMAGES
# =============================================================================

echo -e "\n${PURPLE}🏗️  STEP 2: BUILDING ALL IMAGES${NC}"
echo -e "${PURPLE}===============================================================================${NC}"

# Build function with error handling and timing
build_component() {
    local component=$1
    local dockerfile=$2
    local start_time=$(date +%s)
    
    echo -e "\n${BLUE}📦 Building ${component}...${NC}"
    echo -e "${BLUE}───────────────────────────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}🐋 Dockerfile: ${dockerfile}${NC}"
    echo -e "${CYAN}🏷️  Tags: latest, ${VERSION_TAG}${NC}"
    
    if docker build \
        -f "${dockerfile}" \
        -t "${PROJECT_NAME}/${component}:latest" \
        -t "${PROJECT_NAME}/${component}:${VERSION_TAG}" \
        -t "${PROJECT_NAME}/${component}:build_${BUILD_DATE}" \
        --build-arg BUILD_DATE="${BUILD_DATE}" \
        --build-arg GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
        . ; then
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo -e "${GREEN}✅ ${component} built successfully in ${duration}s${NC}"
        
        # Show image info
        local image_size=$(docker images "${PROJECT_NAME}/${component}:latest" --format "table {{.Size}}" | tail -n 1)
        echo -e "${GREEN}📊 Image size: ${image_size}${NC}"
        
        return 0
    else
        echo -e "${RED}❌ ${component} build FAILED${NC}"
        return 1
    fi
}

# Build results tracking
declare -a BUILD_SUCCESS=()
declare -a BUILD_FAILED=()
TOTAL_START_TIME=$(date +%s)

# Build each component
echo -e "${PURPLE}Building components in order...${NC}\n"

# 1. Sniffer (base component)
if build_component "sniffer" "infrastructure/docker/Dockerfile-sniffer"; then
    BUILD_SUCCESS+=("sniffer")
else
    BUILD_FAILED+=("sniffer")
fi

# 2. GeoIP (base component)  
if build_component "geoip" "infrastructure/docker/Dockerfile-geoip"; then
    BUILD_SUCCESS+=("geoip")
else
    BUILD_FAILED+=("geoip")
fi

# 3. ML Detector (depends on geoip)
if build_component "ml-detector" "infrastructure/docker/Dockerfile-ml-detector"; then
    BUILD_SUCCESS+=("ml-detector")
else
    BUILD_FAILED+=("ml-detector")
fi

# 4. Scheduler (core component)
if build_component "scheduler" "infrastructure/docker/Dockerfile-scheduler"; then
    BUILD_SUCCESS+=("scheduler")
else
    BUILD_FAILED+=("scheduler")
fi

# 5. Simple Firewall Agent
if build_component "simple-firewall-agent" "infrastructure/docker/Dockerfile-simple-firewall-agent"; then
    BUILD_SUCCESS+=("simple-firewall-agent")
else
    BUILD_FAILED+=("simple-firewall-agent")
fi

# 6. Dashboard (web interface)
if build_component "dashboard" "infrastructure/docker/Dockerfile-dashboard"; then
    BUILD_SUCCESS+=("dashboard")
else
    BUILD_FAILED+=("dashboard")
fi

# =============================================================================
# STEP 3: BUILD SUMMARY AND VERIFICATION
# =============================================================================

TOTAL_END_TIME=$(date +%s)
TOTAL_DURATION=$((TOTAL_END_TIME - TOTAL_START_TIME))

echo -e "\n${CYAN}===============================================================================${NC}"
echo -e "${CYAN} 📊 BUILD SUMMARY${NC}"
echo -e "${CYAN}===============================================================================${NC}"
echo -e "${BLUE}⏱️  Total build time: ${TOTAL_DURATION}s ($(($TOTAL_DURATION / 60))m $(($TOTAL_DURATION % 60))s)${NC}"
echo -e "${BLUE}📅 Build completed: $(date)${NC}"

# Success summary
if [ ${#BUILD_SUCCESS[@]} -gt 0 ]; then
    echo -e "\n${GREEN}✅ SUCCESSFUL BUILDS (${#BUILD_SUCCESS[@]}):${NC}"
    for component in "${BUILD_SUCCESS[@]}"; do
        echo -e "${GREEN}   🎉 ${component}${NC}"
    done
fi

# Failure summary
if [ ${#BUILD_FAILED[@]} -gt 0 ]; then
    echo -e "\n${RED}❌ FAILED BUILDS (${#BUILD_FAILED[@]}):${NC}"
    for component in "${BUILD_FAILED[@]}"; do
        echo -e "${RED}   💥 ${component}${NC}"
    done
    echo -e "\n${RED}🚨 Some builds failed! Check the output above for details.${NC}"
fi

# =============================================================================
# STEP 4: IMAGE VERIFICATION
# =============================================================================

echo -e "\n${PURPLE}🔍 STEP 4: IMAGE VERIFICATION${NC}"
echo -e "${PURPLE}===============================================================================${NC}"

echo -e "${BLUE}📋 Available Images:${NC}"
docker images | grep "${PROJECT_NAME}" | sort

# Calculate total size
echo -e "\n${BLUE}💾 Storage Usage:${NC}"
TOTAL_SIZE=$(docker images | grep "${PROJECT_NAME}" | awk '{sum += $NF} END {print sum}' 2>/dev/null || echo "Unknown")
echo -e "${CYAN}📊 Total images size: $(docker images | grep "${PROJECT_NAME}" | awk '{print $7}' | sed 's/MB//' | sed 's/GB/*1000/' | bc 2>/dev/null | awk '{sum+=$1} END {if(sum>1000) printf "%.1fGB\n", sum/1000; else printf "%.0fMB\n", sum}' 2>/dev/null || echo "Unknown")${NC}"

# =============================================================================
# STEP 5: NEXT STEPS INFORMATION
# =============================================================================

echo -e "\n${CYAN}===============================================================================${NC}"
echo -e "${CYAN} 🎯 NEXT STEPS${NC}"
echo -e "${CYAN}===============================================================================${NC}"

if [ ${#BUILD_FAILED[@]} -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL IMAGES BUILT SUCCESSFULLY!${NC}"
    echo -e "\n${BLUE}Ready for:${NC}"
    echo -e "${GREEN}   1. 🚀 Deploy with docker-compose${NC}"
    echo -e "${GREEN}   2. ☸️  Deploy to Kubernetes${NC}"
    echo -e "${GREEN}   3. 🧪 Run integration tests${NC}"
    echo -e "${GREEN}   4. 📊 Monitor components${NC}"
    
    echo -e "\n${BLUE}Quick start commands:${NC}"
    echo -e "${CYAN}   # Start all services${NC}"
    echo -e "${CYAN}   docker-compose up -d${NC}"
    echo -e "${CYAN}   # View logs${NC}"
    echo -e "${CYAN}   docker-compose logs -f${NC}"
    echo -e "${CYAN}   # Check status${NC}"
    echo -e "${CYAN}   docker-compose ps${NC}"
    
else
    echo -e "${RED}⚠️  SOME BUILDS FAILED${NC}"
    echo -e "\n${YELLOW}🔧 Recommended actions:${NC}"
    echo -e "${YELLOW}   1. Check Dockerfile syntax for failed components${NC}"
    echo -e "${YELLOW}   2. Verify all required files exist${NC}"
    echo -e "${YELLOW}   3. Check Docker daemon status${NC}"
    echo -e "${YELLOW}   4. Retry individual builds with -v flag for details${NC}"
    
    echo -e "\n${BLUE}Retry individual build:${NC}"
    for component in "${BUILD_FAILED[@]}"; do
        echo -e "${CYAN}   docker build -f infrastructure/docker/Dockerfile-${component} -t ${PROJECT_NAME}/${component}:latest .${NC}"
    done
fi

echo -e "\n${CYAN}===============================================================================${NC}"
echo -e "${CYAN} 🏁 BUILD SCRIPT COMPLETED${NC}"
echo -e "${CYAN}===============================================================================${NC}"

# Exit with appropriate code
if [ ${#BUILD_FAILED[@]} -gt 0 ]; then
    exit 1
else
    exit 0
fi