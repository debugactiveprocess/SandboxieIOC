TEMPLATE = app
TARGET = SandboxieIOC
CONFIG += console
CONFIG -= app_bundle
QT += core concurrent

# QSbieAPI is normally built as an MSVC DLL, but this tool is built with the
# MinGW Qt kit. MSVC and MinGW C++ ABIs are not compatible, so instead of
# linking QSbieAPI.dll we compile the QSbieAPI sources into this executable.
DEFINES += BUILD_STATIC
# MinGW's dbghelp.h lacks CBA_XML_LOG (present in the Windows SDK). This is a
# compile-time-only enum value used by DbgHelper.cpp for symbol callback logging.
DEFINES += CBA_XML_LOG=0x90000000

INCLUDEPATH += . ../QSbieAPI
DEPENDPATH += . ../QSbieAPI

# ---- QSbieAPI sources & headers (headers listed so qmake runs moc) ----
HEADERS += \
    htmlreport.h \
    ../QSbieAPI/qsbieapi_global.h \
    ../QSbieAPI/SbieDefs.h \
    ../QSbieAPI/SbieUtils.h \
    ../QSbieAPI/SbieAPI.h \
    ../QSbieAPI/SbieTrace.h \
    ../QSbieAPI/SbieStatus.h \
    ../QSbieAPI/Sandboxie/BoxedProcess.h \
    ../QSbieAPI/Sandboxie/SandBox.h \
    ../QSbieAPI/Sandboxie/SbieIni.h \
    ../QSbieAPI/Sandboxie/BoxBorder.h \
    ../QSbieAPI/Sandboxie/SbieTemplates.h \
    ../QSbieAPI/Helpers/NtIO.h \
    ../QSbieAPI/Helpers/DbgHelper.h

SOURCES += \
    main.cpp \
    htmlreport.cpp \
    ../QSbieAPI/SbieAPI.cpp \
    ../QSbieAPI/SbieTrace.cpp \
    ../QSbieAPI/SbieUtils.cpp \
    ../QSbieAPI/Sandboxie/BoxBorder.cpp \
    ../QSbieAPI/Sandboxie/BoxedProcess.cpp \
    ../QSbieAPI/Sandboxie/SandBox.cpp \
    ../QSbieAPI/Sandboxie/SbieIni.cpp \
    ../QSbieAPI/Sandboxie/SbieTemplates.cpp \
    ../QSbieAPI/Helpers/NtIO.cpp \
    ../QSbieAPI/Helpers/DbgHelper.cpp

LIBS += -lntdll -ladvapi32 -lole32 -loleaut32 -luuid -luser32 -lshell32 -lgdi32
