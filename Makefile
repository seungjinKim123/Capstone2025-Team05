# GovScan - 정부기관 네트워크 보안점검 자동화 도구
# 종합 Makefile

# 변수 설정
PYTHON = python3
VENV_DIR = venv
PIP = $(VENV_DIR)/bin/pip
PYTHON_VENV = $(VENV_DIR)/bin/python
REQUIREMENTS = requirements.txt

# 기본 설정
.PHONY: all help setup install test test-cli test-web clean clean-all \
        extract scan parse analyze report dev-setup check-deps \
        check-nmap run-cli run-web backup restore

# 기본 대상
all: help

# 도움말 표시
help:
	@echo "🛡️  GovScan - 정부기관 네트워크 보안점검 자동화 도구"
	@echo "=============================================================="
	@echo ""
	@echo "📋 주요 명령어:"
	@echo "  make setup          - 개발 환경 설정 (venv + 패키지 설치)"
	@echo "  make install        - 필수 패키지만 설치"
	@echo "  make check-deps     - 의존성 확인"
	@echo "  make test           - 전체 테스트 실행"
	@echo "  make test-cli       - CLI 모드 테스트"
	@echo "  make test-web       - 웹 모드 테스트"
	@echo ""
	@echo "🔧 개발 명령어:"
	@echo "  make dev-setup      - 개발 환경 전체 설정"
	@echo "  make run-cli        - CLI 모드 실행"
	@echo "  make run-web        - 웹 모드 실행"
	@echo ""
	@echo "📦 단계별 실행:"
	@echo "  make extract        - IP 추출"
	@echo "  make scan           - Nmap 스캔"
	@echo "  make parse          - XML 파싱"
	@echo "  make analyze        - 취약점 분석"
	@echo "  make report         - 보고서 생성"
	@echo ""
	@echo "🧹 정리 명령어:"
	@echo "  make clean          - 임시 파일 정리"
	@echo "  make clean-all      - 전체 정리 (venv 포함)"
	@echo ""

# =============================================================================
# 환경 설정
# =============================================================================

# 개발 환경 전체 설정
dev-setup: setup check-nmap create-sample-data
	@echo "✅ 개발 환경 설정이 완료되었습니다!"
	@echo ""
	@echo "🚀 사용 방법:"
	@echo "  make test-cli       # CLI 테스트"
	@echo "  make test-web       # 웹 테스트"
	@echo "  make run-web        # 웹 서버 실행"

# 기본 환경 설정 (venv + 패키지)
setup: venv install create-dirs
	@echo "✅ 기본 환경 설정 완료"

# 가상환경 생성
venv:
	@echo "🐍 Python 가상환경 생성 중..."
	$(PYTHON) -m venv $(VENV_DIR)
	@echo "✅ 가상환경 생성 완료: $(VENV_DIR)/"

# 필수 패키지 설치
install: $(REQUIREMENTS)
	@echo "📦 필수 패키지 설치 중..."
	@if [ -f $(PIP) ]; then \
		$(PIP) install --upgrade pip; \
		$(PIP) install -r $(REQUIREMENTS); \
	else \
		echo "❌ 가상환경이 없습니다. 'make venv' 먼저 실행하세요."; \
		exit 1; \
	fi
	@echo "✅ 패키지 설치 완료"

# requirements.txt 생성 (없는 경우)
$(REQUIREMENTS):
	@echo "📝 requirements.txt 생성 중..."
	@cat > $(REQUIREMENTS) << 'EOF'
# GovScan 필수 패키지
flask>=2.3.0
jinja2>=3.1.0
pandas>=1.5.0
packaging>=21.0
werkzeug>=2.3.0

# 추가 유틸리티
requests>=2.28.0
openpyxl>=3.0.0
lxml>=4.9.0

# 개발용 (선택사항)
pytest>=7.0.0
black>=22.0.0
flake8>=5.0.0
EOF
	@echo "✅ requirements.txt 생성 완료"

# 필요한 디렉토리 생성
create-dirs:
	@echo "📁 디렉토리 구조 생성 중..."
	@mkdir -p data/{input,ip_ranges,scan_results,mmdb,reports,scripts,uploads,db}
	@mkdir -p backend/{extract_ip,scanner,mmdb,vuln_checker,report}
	@mkdir -p templates static
	@echo "✅ 디렉토리 생성 완료"

# 샘플 데이터 생성
create-sample-data:
	@echo "📄 샘플 데이터 생성 중..."
	@if [ ! -f data/input/sample_network.csv ]; then \
		cat > data/input/sample_network.csv << 'EOF'; \
IP주소,서비스명,담당부서,비고; \
192.168.1.0/24,내부네트워크,IT팀,테스트용; \
10.0.0.1,웹서버,개발팀,샘플; \
172.16.0.0/16,사무망,총무팀,예시; \
EOF \
		echo "✅ 샘플 CSV 파일 생성: data/input/sample_network.csv"; \
	fi
	@if [ ! -f data/db/eval_db.json ]; then \
		cat > data/db/eval_db.json << 'EOF'; \
{ \
  "version": "1.0", \
  "categories": [ \
    { \
      "id": "network", \
      "name": "네트워크 보안", \
      "checks": [ \
        { \
          "id": "open_ports", \
          "name": "불필요한 포트 개방 점검", \
          "severity": "medium" \
        } \
      ] \
    } \
  ] \
} \
EOF \
		echo "✅ 샘플 평가 DB 생성: data/db/eval_db.json"; \
	fi

# =============================================================================
# 의존성 확인
# =============================================================================

# 전체 의존성 확인
check-deps: check-python check-nmap check-packages
	@echo "✅ 모든 의존성 확인 완료"

# Python 확인
check-python:
	@echo "🐍 Python 확인 중..."
	@$(PYTHON) --version || (echo "❌ Python3가 설치되지 않았습니다" && exit 1)
	@echo "✅ Python 확인 완료"

# Nmap 확인
check-nmap:
	@echo "🔍 Nmap 확인 중..."
	@nmap --version > /dev/null 2>&1 || (echo "⚠️  Nmap이 설치되지 않았습니다" && \
		echo "🔧 설치 방법:" && \
		echo "  Ubuntu/Debian: sudo apt-get install nmap" && \
		echo "  CentOS/RHEL:   sudo yum install nmap" && \
		echo "  macOS:         brew install nmap" && \
		echo "  Windows:       https://nmap.org/download.html")
	@echo "✅ Nmap 확인 완료"

# Python 패키지 확인
check-packages:
	@echo "📦 Python 패키지 확인 중..."
	@if [ -f $(PYTHON_VENV) ]; then \
		$(PYTHON_VENV) -c "import flask, jinja2, pandas, packaging" 2>/dev/null || \
		(echo "❌ 필수 패키지가 누락되었습니다. 'make install' 실행하세요" && exit 1); \
	else \
		$(PYTHON) -c "import flask, jinja2, pandas, packaging" 2>/dev/null || \
		(echo "❌ 필수 패키지가 누락되었습니다. 'make setup' 실행하세요" && exit 1); \
	fi
	@echo "✅ 패키지 확인 완료"

# =============================================================================
# 테스트 실행
# =============================================================================

# 전체 테스트
test: test-cli test-web
	@echo "🎉 모든 테스트 완료!"

# CLI 테스트
test-cli: check-deps
	@echo "🚀 CLI 모드 테스트 시작..."
	@if [ -f $(PYTHON_VENV) ]; then \
		echo "📝 CLI 버전 정보:"; \
		$(PYTHON_VENV) main.py --help | head -5; \
		echo ""; \
		echo "📋 CLI 의존성 확인:"; \
		$(PYTHON_VENV) -c "from backend.extract_ip.extractor import extract_ip_ranges; print('✅ IP 추출 모듈')"; \
		echo "📊 샘플 스캔 테스트 (TCP 모드):"; \
		$(PYTHON_VENV) main.py scan data/input/sample_network.csv --tcp --name test_cli 2>&1 | head -20 || true; \
	else \
		echo "📝 CLI 버전 정보:"; \
		$(PYTHON) main.py --help | head -5; \
		echo ""; \
		echo "📋 CLI 의존성 확인:"; \
		$(PYTHON) -c "from backend.extract_ip.extractor import extract_ip_ranges; print('✅ IP 추출 모듈')"; \
		echo "📊 샘플 스캔 테스트 (TCP 모드):"; \
		$(PYTHON) main.py scan data/input/sample_network.csv --tcp --name test_cli 2>&1 | head -20 || true; \
	fi
	@echo "✅ CLI 테스트 완료"

# 웹 테스트
test-web: check-deps
	@echo "🌐 웹 모드 테스트 시작..."
	@if [ -f $(PYTHON_VENV) ]; then \
		echo "📝 웹서버 모듈 확인:"; \
		$(PYTHON_VENV) -c "from web_server import app; print('✅ 웹서버 모듈 로드 완료')"; \
		echo "🔧 웹서버 설정 확인:"; \
		$(PYTHON_VENV) -c "from web_server import app; print(f'✅ Flask 앱: {app.name}')"; \
		echo ""; \
		echo "🚀 웹서버 시작 테스트 (5초 후 종료):"; \
		timeout 5 $(PYTHON_VENV) main.py web 2>&1 | head -10 || echo "✅ 웹서버 시작 테스트 완료"; \
	else \
		echo "📝 웹서버 모듈 확인:"; \
		$(PYTHON) -c "from web_server import app; print('✅ 웹서버 모듈 로드 완료')"; \
		echo "🔧 웹서버 설정 확인:"; \
		$(PYTHON) -c "from web_server import app; print(f'✅ Flask 앱: {app.name}')"; \
		echo ""; \
		echo "🚀 웹서버 시작 테스트 (5초 후 종료):"; \
		timeout 5 $(PYTHON) main.py web 2>&1 | head -10 || echo "✅ 웹서버 시작 테스트 완료"; \
	fi
	@echo "✅ 웹 테스트 완료"

# =============================================================================
# 실행 명령어
# =============================================================================

# CLI 실행
run-cli:
	@echo "🚀 CLI 모드 실행..."
	@echo "사용법: make run-cli FILE=data/input/sample_network.csv"
	@FILE=$${FILE:-data/input/sample_network.csv}; \
	if [ -f $(PYTHON_VENV) ]; then \
		$(PYTHON_VENV) main.py scan "$$FILE" --tcp; \
	else \
		$(PYTHON) main.py scan "$$FILE" --tcp; \
	fi

# 웹 실행
run-web:
	@echo "🌐 웹 모드 실행..."
	@if [ -f $(PYTHON_VENV) ]; then \
		$(PYTHON_VENV) main.py web; \
	else \
		$(PYTHON) main.py web; \
	fi

# =============================================================================
# 단계별 실행 (기존 호환)
# =============================================================================

# 1. IP 추출
extract:
	@echo "📥 [1/5] IP 대역 추출 중..."
	@if [ -f $(PYTHON_VENV) ]; then \
		$(PYTHON_VENV) -c "from backend.extract_ip.extractor import extract_ip_ranges; \
		result = extract_ip_ranges('data/input/sample_network.csv', 'data/ip_ranges/ip_list.txt', 'data/ip_ranges/ip_cidr.txt'); \
		print(f'✅ {result}개 IP 추출 완료')"; \
	else \
		$(PYTHON) -c "from backend.extract_ip.extractor import extract_ip_ranges; \
		result = extract_ip_ranges('data/input/sample_network.csv', 'data/ip_ranges/ip_list.txt', 'data/ip_ranges/ip_cidr.txt'); \
		print(f'✅ {result}개 IP 추출 완료')"; \
	fi

# 2. Nmap 스캔
scan:
	@echo "🔍 [2/5] Nmap 스캔 실행 중..."
	@if [ ! -f data/ip_ranges/ip_cidr.txt ]; then \
		echo "❌ IP 목록이 없습니다. 'make extract' 먼저 실행하세요."; \
		exit 1; \
	fi
	@if [ -f $(PYTHON_VENV) ]; then \
		$(PYTHON_VENV) -c "from backend.scanner.nmap_runner import run_nmap_scan; \
		result = run_nmap_scan('data/ip_ranges/ip_cidr.txt', 'data/scan_results', '1-1000', '-sT'); \
		print(f'✅ 스캔 완료: {result}' if result else '❌ 스캔 실패')"; \
	else \
		$(PYTHON) -c "from backend.scanner.nmap_runner import run_nmap_scan; \
		result = run_nmap_scan('data/ip_ranges/ip_cidr.txt', 'data/scan_results', '1-1000', '-sT'); \
		print(f'✅ 스캔 완료: {result}' if result else '❌ 스캔 실패')"; \
	fi

# 3. XML 파싱
parse:
	@echo "📦 [3/5] XML 파싱 중..."
	@XML_FILE=$$(ls data/scan_results/*.xml 2>/dev/null | head -1); \
	if [ -z "$$XML_FILE" ]; then \
		echo "❌ XML 파일이 없습니다. 'make scan' 먼저 실행하세요."; \
		exit 1; \
	fi; \
	if [ -f $(PYTHON_VENV) ]; then \
		$(PYTHON_VENV) -c "from backend.mmdb.mmdb_converter import parse_nmap_xml; \
		parse_nmap_xml('$$XML_FILE', 'data/mmdb/scan_parsed.json'); \
		print('✅ XML 파싱 완료')"; \
	else \
		$(PYTHON) -c "from backend.mmdb.mmdb_converter import parse_nmap_xml; \
		parse_nmap_xml('$$XML_FILE', 'data/mmdb/scan_parsed.json'); \
		print('✅ XML 파싱 완료')"; \
	fi

# 4. 취약점 분석
analyze:
	@echo "🧠 [4/5] 취약점 분석 중..."
	@if [ ! -f data/mmdb/scan_parsed.json ]; then \
		echo "❌ 파싱된 데이터가 없습니다. 'make parse' 먼저 실행하세요."; \
		exit 1; \
	fi
	@if [ -f $(PYTHON_VENV) ]; then \
		$(PYTHON_VENV) -c "from backend.vuln_checker.core import run_all_checks; \
		import json; \
		result = run_all_checks(); \
		with open('data/reports/analysis_results.json', 'w') as f: json.dump(result, f, indent=2); \
		print('✅ 취약점 분석 완료')"; \
	else \
		$(PYTHON) -c "from backend.vuln_checker.core import run_all_checks; \
		import json; \
		result = run_all_checks(); \
		with open('data/reports/analysis_results.json', 'w') as f: json.dump(result, f, indent=2); \
		print('✅ 취약점 분석 완료')"; \
	fi

# 5. 보고서 생성
report:
	@echo "📝 [5/5] 보고서 생성 중..."
	@if [ ! -f data/reports/analysis_results.json ]; then \
		echo "❌ 분석 결과가 없습니다. 'make analyze' 먼저 실행하세요."; \
		exit 1; \
	fi
	@if [ -f $(PYTHON_VENV) ]; then \
		$(PYTHON_VENV) -c "from backend.report.generator import generate_comprehensive_report; \
		result = generate_comprehensive_report('data/reports/analysis_results.json', 'data/db/eval_db.json', 'data/reports'); \
		print('✅ 보고서 생성 완료')"; \
	else \
		$(PYTHON) -c "from backend.report.generator import generate_comprehensive_report; \
		result = generate_comprehensive_report('data/reports/analysis_results.json', 'data/db/eval_db.json', 'data/reports'); \
		print('✅ 보고서 생성 완료')"; \
	fi

# 전체 단계 실행
pipeline: extract scan parse analyze report
	@echo "🎉 전체 파이프라인 완료!"

# =============================================================================
# 정리 명령어
# =============================================================================

# 임시 파일 정리
clean:
	@echo "🧹 임시 파일 정리 중..."
	@rm -f data/ip_ranges/*.txt
	@rm -f data/scan_results/*
	@rm -f data/mmdb/*.json
	@rm -f data/reports/*.json
	@rm -f data/reports/*.html
	@rm -f *.log
	@echo "✅ 정리 완료"

# 전체 정리 (가상환경 포함)
clean-all: clean
	@echo "🧹 전체 정리 중 (가상환경 포함)..."
	@rm -rf $(VENV_DIR)
	@rm -rf __pycache__ backend/__pycache__ backend/*/__pycache__
	@rm -f *.pyc backend/*.pyc backend/*/*.pyc
	@echo "✅ 전체 정리 완료"

# 백업
backup:
	@echo "💾 백업 생성 중..."
	@BACKUP_NAME="govscan_backup_$(shell date +%Y%m%d_%H%M%S).tar.gz"; \
	tar -czf "$$BACKUP_NAME" \
		--exclude=venv \
		--exclude=__pycache__ \
		--exclude="*.pyc" \
		--exclude=".git" \
		. ; \
	echo "✅ 백업 완료: $$BACKUP_NAME"

# 상태 확인
status:
	@echo "📊 GovScan 상태 확인"
	@echo "===================="
	@echo "🐍 Python 가상환경: $$([ -d $(VENV_DIR) ] && echo '✅ 설치됨' || echo '❌ 없음')"
	@echo "📦 필수 패키지: $$($(PYTHON) -c 'import flask,jinja2,pandas,packaging' 2>/dev/null && echo '✅ 설치됨' || echo '❌ 없음')"
	@echo "🔍 Nmap: $$(nmap --version >/dev/null 2>&1 && echo '✅ 설치됨' || echo '❌ 없음')"
	@echo "📁 데이터 디렉토리: $$([ -d data ] && echo '✅ 존재함' || echo '❌ 없음')"
	@echo "📄 샘플 데이터: $$([ -f data/input/sample_network.csv ] && echo '✅ 준비됨' || echo '❌ 없음')"
	@echo ""
	@echo "📈 최근 파일들:"
	@ls -la data/reports/ 2>/dev/null | tail -3 || echo "  (보고서 없음)"