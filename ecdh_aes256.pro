TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lpthread -lssl -lcrypto

SOURCES += \
        main.cpp \
        security.cpp

HEADERS += \
    byte_array.hpp \
    security.hpp
