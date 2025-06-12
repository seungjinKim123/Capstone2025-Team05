# GovScan - 네트워크 보안점검 자동화 도구

🛡️ **GovScan**은 정부기관 및 공공기관의 네트워크 보안점검을 자동화하는 종합 도구입니다. IP 관리대장으로부터 자동으로 대상을 추출하고, Nmap을 이용한 네트워크 스캔, 취약점 분석, 그리고 전문적인 보고서 생성까지 원스톱으로 제공합니다.

## 🚀 주요 기능

### 1. 자동화된 스캔 프로세스
- **IP 대역 추출**: CSV/Excel 관리대장에서 IP 자동 추출 및 CIDR 최적화
- **네트워크 스캔**: Nmap을 이용한 포트 스캔, 서비스 탐지, OS 핑거프린팅
- **취약점 분석**: CVE 데이터베이스 기반 취약점 탐지 및 보안정책 위반 사항 점검

### 2. 전문적인 보고서
- **시각화된 HTML 보고서**: 반응형 디자인, 위험도별 색상 구분, 통계 대시보드
- **점검 스크립트 제공**: 각 취약점별 Shell 스크립트 자동 생성 및 다운로드
- **체크리스트 문서**: 수동 점검을 위한 상세 체크리스트 제공

### 3. 웹 GUI 인터페이스
- **직관적인 대시보드**: 스캔 현황, 진행 상태, 히스토리 관리
- **실시간 모니터링**: 스캔 진행률 실시간 표시, 백그라운드 작업 관리
- **파일 관리**: 드래그 앤 드롭 업로드, 원클릭 다운로드

## 📋 시스템 요구사항

### 필수 요구사항
- **운영체제**: Linux, macOS, Windows 10/11
- **Python**: 3.8 이상
- **Nmap**: 7.0 이상 (시스템에 설치 필요)
- **메모리**: 최소 4GB RAM
- **디스크**: 최소 2GB 여유 공간

### 권한 요구사항
- **Nmap 실행**: SYN 스캔을 위해 관리자 권한 필요
- **포트 접근**: 네트워크 연결을 위한 방화벽 설정

## 🚀 빠른 시작 (Makefile 사용)

GovScan은 Makefile을 통해 전체 개발 환경 설정부터 테스트까지 한 번에 실행할 수 있습니다.

### 원클릭 설치 및 설정
```bash
# 1. 전체 개발 환경 자동 설정 (가상환경 + 패키지 + 샘플 데이터)
make dev-setup

# 2. 설치 확인 및 테스트
make test
```

### 일반 설치 과정
```bash
# 1. 기본 환경 설정 (가상환경 + 패키지)
make setup

# 2. 의존성 확인
make check-deps

# 3. CLI 테스트
make test-cli

# 4. 웹 테스트
make test-web
```

### Makefile 주요 명령어

#### 🔧 환경 설정
```bash
make setup          # 기본 환경 설정 (venv + 패키지)
make dev-setup       # 개발 환경 전체 설정 (샘플 데이터 포함)
make install         # 필수 패키지만 설치
make check-deps      # 전체 의존성 확인
make status          # 현재 설치 상태 확인
```

#### 🧪 테스트 실행
```bash
make test           # 전체 테스트 (CLI + 웹)
make test-cli       # CLI 모드 테스트
make test-web       # 웹 모드 테스트 (5초 시작 테스트)
```

#### 🚀 실행
```bash
make run-web        # 웹 서버 실행
make run-cli        # CLI 스캔 실행 (샘플 데이터)
make run-cli FILE=my_network.csv  # 특정 파일로 CLI 실행
```

#### 📋 단계별 실행 (고급 사용자)
```bash
make extract        # 1단계: IP 추출
make scan           # 2단계: Nmap 스캔
make parse          # 3단계: XML 파싱
make analyze        # 4단계: 취약점 분석
make report         # 5단계: 보고서 생성
make pipeline       # 전체 단계 한 번에 실행
```

#### 🧹 정리
```bash
make clean          # 임시 파일 정리
make clean-all      # 전체 정리 (가상환경 포함)
make backup         # 현재 상태 백업
```

### 자동 생성되는 파일들

Makefile 실행 시 다음 파일들이 자동으로 생성됩니다:

```bash
requirements.txt                    # Python 패키지 목록
data/input/sample_network.csv       # 테스트용 샘플 CSV
data/db/eval_db.json               # 샘플 평가 데이터베이스
venv/                              # Python 가상환경
```

### 빠른 시작 가이드

#### 첫 사용자 (완전 자동 설정)
```bash
git clone https://github.com/your-org/govscan.git
cd govscan
make dev-setup      # 모든 것 자동 설정
make run-web        # 웹서버 실행
```

#### 개발자 (단계별 설정)
```bash
git clone https://github.com/your-org/govscan.git
cd govscan
make setup          # 기본 환경만
make check-nmap     # Nmap 설치 확인
make test-cli       # CLI 테스트
make run-web        # 웹서버 실행
```

### 문제 해결

#### 의존성 문제
```bash
make status         # 현재 상태 확인
make check-deps     # 누락된 패키지 확인
make clean-all      # 전체 초기화 후 재설치
make dev-setup
```

#### Nmap 설치 확인
```bash
make check-nmap     # Nmap 설치 상태 확인
# 설치 방법이 자동으로 표시됩니다
```

#### 전체 재설정
```bash
make clean-all      # 모든 설정 삭제
make dev-setup      # 처음부터 다시 설정
```

### 고급 사용법

#### 커스텀 파일로 테스트
```bash
# 특정 CSV 파일로 CLI 스캔
make run-cli FILE=data/input/my_network.csv

# 샘플 데이터 재생성
rm data/input/sample_network.csv
make create-sample-data
```

#### 백업 및 복원
```bash
# 현재 상태 백업
make backup         # govscan_backup_YYYYMMDD_HHMMSS.tar.gz 생성

# 상태 확인
make status         # 설치된 구성 요소 확인
```

이 방법을 사용하면 복잡한 설치 과정 없이 한 번의 명령으로 GovScan을 사용할 수 있습니다.

## 🛠️ 설치 방법

### 1. 저장소 복제
```bash
git clone https://github.com/your-org/govscan.git
cd govscan
```

### 2. Python 의존성 설치
```bash
pip install -r requirements.txt
```

### 3. Nmap 설치
**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install nmap
```

**CentOS/RHEL:**
```bash
sudo yum install nmap
```

**macOS:**
```bash
brew install nmap
```

**Windows:**
- [Nmap 공식 사이트](https://nmap.org/download.html)에서 다운로드 및 설치

### 4. 디렉토리 구조 확인
```
govscan/
├── backend/
│   ├── extract_ip/
│   ├── scanner/
│   ├── mmdb/
│   ├── vuln_checker/
│   ├── report/
│   └── templates/
├── data/
│   ├── db/
│   ├── input/
│   └── reports/
└── main.py
```

## 🖥️ 사용 방법

### 웹 GUI 실행 (권장)
```bash
python main.py web
```
브라우저에서 `http://localhost:5000` 접속

### CLI 실행
```bash
# 전체 스캔 실행
python main.py scan data/input/network.csv

# 스캔명 지정
python main.py scan data/input/network.csv --name "2025년_1분기_점검"

# 기존 결과로 보고서만 생성
python main.py report data/reports/analysis_results.json

# 점검 스크립트만 생성
python main.py generate-scripts
```

## 📊 입력 파일 형식

### IP 관리대장 (CSV/Excel)
```csv
Container,Role,IP Address,Services,Network
admin,Security Scanner,192.168.1.10,nmap,shared_net
db,Database Server,192.168.2.10,PostgreSQL,shared_net
web,Web Server,192.168.1.0/24,HTTP/HTTPS,dmz_net
```

**지원 형식:**
- 단일 IP: `192.168.1.10`
- IP 범위: `192.168.1.10-192.168.1.20`
- CIDR 표기: `192.168.1.0/24`

## 🔍 점검 항목

| 코드 | 점검 항목 | 설명 |
|------|-----------|------|
| 11303 | 관리대장 누락 | 미등록 자산 탐지 |
| 20501 | 접근통제 미흡 | 익명 접속, 기본 계정 사용 |
| 20502 | SSH 약한 인증 | SSH 보안 설정 점검 |
| 20503 | 취약한 서비스 | Telnet, FTP 등 위험 서비스 |
| 30301 | 네트워크 관리대장 | 물리적 연결 장비 관리 |
| 30501 | 불필요한 서비스 | 업무 무관 서비스 실행 |
| 30601 | SNMP 보안 설정 | 기본 커뮤니티 스트링 사용 |
| 30701 | 웹 서버 보안 | 디렉토리 리스팅, HTTP 메소드 |
| 30802 | 버전정보 노출 | 서비스 버전 정보 노출 |
| 40101 | 패치 관리 | 보안 패치 적용 상태 |

## 📋 생성되는 결과물

### 1. HTML 보고서
- **위치**: `data/reports/{scan_id}/govscan_report_{timestamp}.html`
- **내용**: 시각화된 점검 결과, 위험도별 분류, CVE 정보
- **기능**: 점검 스크립트 다운로드, 체크리스트 포함

### 2. 점검 스크립트
- **위치**: `data/reports/{scan_id}/scripts/check_scripts.zip`
- **내용**: 각 취약점별 Shell 스크립트
- **용도**: 수동 점검, 정기 모니터링

### 3. 체크리스트 문서
- **위치**: `data/reports/{scan_id}/checklist_{timestamp}.txt`
- **내용**: 점검 체크리스트, 조치 방법
- **용도**: 현장 점검, 교육 자료

### 4. JSON 결과
- **위치**: `data/reports/{scan_id}/analysis_results_{timestamp}.json`
- **내용**: 구조화된 분석 결과
- **용도**: 추가 분석, 외부 시스템 연동

## 🌐 웹 인터페이스 사용법

### 1. 대시보드
- **통계 요약**: 총 스캔 수, 완료/실패/진행 중 현황
- **최근 스캔**: 스캔 히스토리 테이블
- **사이드바**: 과거 스캔 결과 빠른 접근

### 2. 새 스캔 시작
1. **"새 스캔 시작"** 버튼 클릭
2. **스캔명 입력**: 구분하기 쉬운 이름 설정
3. **파일 업로드**: IP 관리대장 CSV/Excel 파일
4. **옵션 설정**: 포트 범위, 스캔 타입 선택
5. **실행**: 실시간 진행률 모니터링

### 3. 결과 확인
- **보고서 보기**: 브라우저에서 HTML 보고서 열기
- **파일 다운로드**: 스크립트, 체크리스트, JSON 일괄 다운로드
- **개별 스크립트**: 특정 점검 스크립트만 다운로드

## ⚙️ 설정 사용자화

### 스캔 옵션
```python
# nmap_runner.py에서 기본값 수정
def run_nmap_scan(
    ports: str = "1-65535",        # 전체 포트 스캔
    scan_type: str = "-sS",        # SYN 스캔
    additional_args: str = "-A"    # 공격적 스캔
):
```

### 점검 규칙 추가
```python
# backend/vuln_checker/rules/에 새 파일 생성
def evaluate(ip: str, host_data: dict) -> list:
    violations = []
    # 커스텀 점검 로직 구현
    return violations
```

### 보고서 템플릿 수정
- **파일**: `backend/report/template/enhanced_report_template.html`
- **스타일**: CSS 수정으로 디자인 변경
- **내용**: Jinja2 템플릿 문법으로 항목 추가

## 🔧 문제 해결

### 일반적인 문제

**1. Nmap 권한 오류**
```bash
# Linux/macOS
sudo python main.py scan input.csv

# Windows (관리자 권한으로 실행)
```

**2. 포트 접근 오류**
```bash
# 방화벽 확인
sudo ufw status
netstat -tlnp | grep :5000
```

**3. 의존성 설치 실패**
```bash
# 가상환경 사용 권장
python -m venv govscan-env
source govscan-env/bin/activate  # Linux/macOS
# govscan-env\Scripts\activate    # Windows
pip install -r requirements.txt
```

### 로그 확인
```bash
# 스캔 로그
tail -f data/scan_results/*/scan_*.nmap

# 웹 서버 로그
python main.py web --debug
```

---

**⚠️ 주의사항**: 이 도구는 승인된 네트워크에서만 사용하세요. 무단 스캔은 법적 문제를 야기할 수 있습니다.