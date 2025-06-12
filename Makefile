# 기본 실행 대상
.PHONY: all test extract scan parse analyze report clean

# 1. IP 추출 (CIDR 생성)
extract:
	@echo "📥 [1/5] Extracting IP ranges from network.csv..."
	python3 backend/extract_ip/extractor.py data/input/network.csv

# 2. Nmap 스캔 (sudo 필요)
scan:
	@echo "🔍 [2/5] Running Nmap scan..."
	python3 backend/scanner/nmap_runner.py data/ip_ranges/ip_cidr.txt

# 3. XML → JSON 변환
parse:
	@echo "📦 [3/5] Parsing Nmap XML results..."
	python3 backend/mmdb/mmdb_converter.py data/scan_results/*.xml

# 4. 취약점/정책 분석
analyze:
	@echo "🧠 [4/5] Running vulnerability & policy checks..."
	python3 -m backend.vuln_checker.core

# 5. HTML 보고서 생성
report:
	@echo "📝 [5/5] Generating HTML report..."
	python3 backend/report/generator.py

# 전체 테스트 실행
all: extract scan parse analyze report

# 별칭
test: all

# 임시 출력 제거
clean:
	rm -f data/ip_ranges/*.txt
	rm -f data/scan_results/*
	rm -f data/mmdb/*.json
	rm -f data/reports/*.json
	rm -f data/reports/*.html
	@echo "🧹 Clean complete."
