# DIR Engine

<p align="center"><img src="http://bafegoist.com/board/eyoom/theme/basic2/image/header_slider/slider_1.jpg"/></p>



== English ==

about DIR Engine
DIR(Disassembly Intermediate Representation) Engine is static analysis engine that support in EGOIST.
DIR Engine is composed mainly of C++. It will be supply Windows, Mac, Linux Platform.
Currently, DIR Engine support only GCC (partly VS). This will be supply both of them.
You can see build and supporting library in the below

0x1. How to build
Install supporting library in the below (0x2) and execute command.
`python setup.py install`

0x2. Supporting Libraries
VEX ( https://github.com/angr/vex )
- Supporting Windows, Linux, MAC, GCC

CAPSTONE ( https://github.com/aquynh/capstone )
- Supporting all Platform, VS, GCC

PyELFtools (https://github.com/eliben/pyelftools)
- for analyzing ELF header

PEFile (https://github.com/erocarrera/pefile)
- for analyzing PE header

0x3. Directory Structure
lib : directory which composed with libraries
test : testcode for verify library code, Example directory
DirEngine : Code

== Korean ==

DIR Engine이란?
Disassembly Intermediate Representation 의 약자로 EGOIST에서 지원하는 정적 분석 엔진이다.
지원 플랫폼은 Windows, MAC, Linux를 지원할 예정이며 C++로 구성되어 있다.
또한 현재 컴파일은(VEX) GCC 만 지원한다. (일부 VS 지원) - 차후 전부 지원 
아래에 보면 빌드에 필요한 방법과 사용하는 라이브러리가 적혀 있다.

0x1. 빌드?
아래 라이브러리들을 설치하시고
python setup.py install 하시면 됩니다.


0x2. 사용 하는 라이브러리
VEX ( https://github.com/angr/vex )
- Windows 외 Linux, MAC 지원 , GCC 지원

CAPSTONE ( https://github.com/aquynh/capstone )
- All Platform 다 지원, VS, GCC 지원

PyELFtools (https://github.com/eliben/pyelftools)
- ELF 헤더 분석

PEFile (https://github.com/erocarrera/pefile)
- PE 헤더 분석


0x3. 폴더 구성
lib : 라이브러리들이 모여있는 폴더
test : 라이브러리 코드 검증, Example 폴더
DirEngine : 실제 코드
