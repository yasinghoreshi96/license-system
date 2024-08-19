/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 5.13.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QToolBar>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralWidget;
    QLineEdit *licenseLineEdit;
    QLabel *statusLabel;
    QPushButton *validateButton;
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QString::fromUtf8("MainWindow"));
        MainWindow->resize(344, 202);
        centralWidget = new QWidget(MainWindow);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        licenseLineEdit = new QLineEdit(centralWidget);
        licenseLineEdit->setObjectName(QString::fromUtf8("licenseLineEdit"));
        licenseLineEdit->setGeometry(QRect(20, 20, 291, 25));
        statusLabel = new QLabel(centralWidget);
        statusLabel->setObjectName(QString::fromUtf8("statusLabel"));
        statusLabel->setGeometry(QRect(20, 50, 291, 41));
        validateButton = new QPushButton(centralWidget);
        validateButton->setObjectName(QString::fromUtf8("validateButton"));
        validateButton->setGeometry(QRect(50, 100, 221, 41));
        MainWindow->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(MainWindow);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 344, 22));
        MainWindow->setMenuBar(menuBar);
        mainToolBar = new QToolBar(MainWindow);
        mainToolBar->setObjectName(QString::fromUtf8("mainToolBar"));
        MainWindow->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(MainWindow);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        MainWindow->setStatusBar(statusBar);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "MainWindow", nullptr));
        MainWindow->setStyleSheet(QCoreApplication::translate("MainWindow", "\n"
"        QMainWindow {\n"
"            background-color: #000000;\n"
"            color: #FFFFFF;\n"
"        }\n"
"        ", nullptr));
        centralWidget->setStyleSheet(QCoreApplication::translate("MainWindow", "\n"
"        QWidget {\n"
"            background-color: #000000;\n"
"            color: #FFFFFF;\n"
"        }\n"
"        ", nullptr));
        licenseLineEdit->setStyleSheet(QCoreApplication::translate("MainWindow", "\n"
"        QLineEdit {\n"
"            background-color: #000000;\n"
"            color: #FFFFFF;\n"
"            border: 1px solid #444444;\n"
"        }\n"
"        ", nullptr));
        statusLabel->setText(QCoreApplication::translate("MainWindow", "s", nullptr));
        statusLabel->setStyleSheet(QCoreApplication::translate("MainWindow", "\n"
"        QLabel {\n"
"            background-color: #000000;\n"
"            color: #FFFFFF;\n"
"            border: 1px solid #444444;\n"
"        }\n"
"        ", nullptr));
        validateButton->setText(QCoreApplication::translate("MainWindow", "validateButton", nullptr));
        validateButton->setStyleSheet(QCoreApplication::translate("MainWindow", "\n"
"        QPushButton {\n"
"            background-color: #333333;\n"
"            color: #FFFFFF;\n"
"            border: 1px solid #444444;\n"
"            padding: 5px;\n"
"        }\n"
"        QPushButton:hover {\n"
"            background-color: #555555;\n"
"        }\n"
"        ", nullptr));
        menuBar->setStyleSheet(QCoreApplication::translate("MainWindow", "\n"
"        QMenuBar {\n"
"            background-color: #000000;\n"
"            color: #FFFFFF;\n"
"        }\n"
"        ", nullptr));
        mainToolBar->setStyleSheet(QCoreApplication::translate("MainWindow", "\n"
"        QToolBar {\n"
"            background-color: #000000;\n"
"            color: #FFFFFF;\n"
"        }\n"
"        ", nullptr));
        statusBar->setStyleSheet(QCoreApplication::translate("MainWindow", "\n"
"        QStatusBar {\n"
"            background-color: #000000;\n"
"            color: #FFFFFF;\n"
"        }\n"
"        ", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
