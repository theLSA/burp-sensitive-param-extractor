#coding:utf-8
#Author:LSA
#Date:20200630
#Description:sensitive parameter extractor-burpsuite extension

import json
import re

from burp import IBurpExtender, ITab, IHttpListener
from javax.swing import JPanel, JLabel, JButton, JTextArea, JTextField, JCheckBox, JTabbedPane, JScrollPane, SwingConstants, JFileChooser, JList, JOptionPane
from java.awt import BorderLayout, Font, Color

from java.io import PrintWriter


# config
paramRegularFile = "param-regular.cfg"

sensitiveParamsFile = "sensitive-params.txt"

# 获取配置文件内容
def getParamRegular():
    paramRegularList = []
    with open(paramRegularFile, 'r') as prf:
        for paramR in prf.readlines():
            paramRegularList.append(paramR.strip())
    return paramRegularList




def getSensitiveParamsFromFile():
    sensitiveParamsList = []
    with open(sensitiveParamsFile, 'r') as spf:
        for sensitiveParam in spf.readlines():
            sensitiveParamsList.append(sensitiveParam.strip())
    return sensitiveParamsList

class BurpExtender(IBurpExtender, ITab,IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("burp-sensitive-param-extractor")
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.registerHttpListener(self)
        #callbacks.registerMessageEditorTabFactory(self)
        print 'burp-sensitive-param-extractor loaded.\nAuthor:LSA\nhttps://github.com/theLSA/burp-sensitive-param-extractor'


        self.sensitiveParamR = getParamRegular()

        self._callbacks.customizeUiComponent(self.getUiComponent())
        self._callbacks.addSuiteTab(self)
        #self.endColors = []
        self.requestParamDict = {}
        self.resultSensitiveParamsDict = {}


    def getTabCaption(self):
        return 'BSPE'


    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        if messageIsRequest and toolFlag==4:
            self.requestParamDict['urlParams'] = []
            self.requestParamDict['BodyParams'] = []
            self.requestParamDict['cookieParams'] = []
            self.requestParamDict['jsonParams'] = []

            cookieParamFlag = 0

            service = messageInfo.getHttpService()
            request = messageInfo.getRequest()
            analyzeReq = self._helpers.analyzeRequest(service,request)
            reqUrl = self._helpers.analyzeRequest(messageInfo).getUrl()
            reqMethod = self._helpers.analyzeRequest(messageInfo).getMethod()


            reqParams = analyzeReq.getParameters()



            for param in reqParams:
                paramType = param.getType()

                if paramType == 0:
                    #self.outputTxtArea.append("\nurlParams-")
                    
                    paramName = param.getName()
                    paramValue = param.getValue()
                    print 'urlParams:'
                    print paramName + ':' + paramValue
                    #self.outputTxtArea.append("[%s]" % paramName)
                    self.requestParamDict['urlParams'].append(paramName.strip())
                    

                if paramType == 1:
                    #self.outputTxtArea.append("\nBodyParams-")
                    
                    paramName = param.getName()
                    paramValue = param.getValue()
                    print 'BodyParams:'
                    print paramName + ':' + paramValue
                    #self.outputTxtArea.append("[%s]\n" % paramName)
                    self.requestParamDict['BodyParams'].append(paramName.strip())

                if paramType == 2:
                    #self.outputTxtArea.append("\ncookieParams-")
                    
                    paramName = param.getName()
                    paramValue = param.getValue()
                    print 'CookieParams:'
                    print paramName + ':' + paramValue
                    #self.outputTxtArea.append("[%s]\n" % paramName)
                    self.requestParamDict['cookieParams'].append(paramName.strip())
                    cookieParamFlag = 1

                if paramType == 6:
                    #self.outputTxtArea.append("\njsonParams-")
                    
                    paramName = param.getName()
                    paramValue = param.getValue()
                    print 'JsonParams:'
                    print paramName + ':' + paramValue
                    #self.outputTxtArea.append("[%s]\n" % paramName)
                    self.requestParamDict['jsonParams'].append(paramName.strip())

            self.resultSensitiveParamsDict = self.findSensitiveParam(self.requestParamDict)
            #print self.resultSensitiveParamsDict


            for rspdKey in self.resultSensitiveParamsDict.keys():
                if self.resultSensitiveParamsDict[rspdKey] != []:
                    print "[%s][%s]" % (reqMethod,reqUrl)
                    self.outputTxtArea.append("\n------------------------------------------------------\n")
                    self.outputTxtArea.append("[%s][%s]\n" % (reqMethod,reqUrl))
                    break

            for rspdKey in self.resultSensitiveParamsDict.keys():
                if self.resultSensitiveParamsDict[rspdKey] != []:    
                    self.outputTxtArea.append("\n"+rspdKey+"--"+str(self.resultSensitiveParamsDict[rspdKey]))

            self.write2file()



            #pass

        else:
            return
        

    def findSensitiveParam(self,requestParamDict):
        #sensitiveParamR = getParamRegular()
        resultSensitiveParamsDict = {}
        resultSensitiveParamsDict['urlParams'] = []

        resultSensitiveParamsDict['BodyParams'] = []

        resultSensitiveParamsDict['cookieParams'] = []

        resultSensitiveParamsDict['jsonParams'] = []

    #print requestParamDict

        for spr in self.sensitiveParamR:
            for key in requestParamDict.keys():
                for reqParam in requestParamDict[key]:
                    if len(spr)==1:
                        if spr == reqParam.lower():
                            resultSensitiveParamsDict[key].append(reqParam)
                    else:
                        if spr in reqParam.lower():
                            print spr + ' in ' + reqParam
                            resultSensitiveParamsDict[key].append(reqParam)
        #print resultSensitiveParamsDict
        for key in resultSensitiveParamsDict.keys():
            resultSensitiveParamsDict[key] = {}.fromkeys(resultSensitiveParamsDict[key]).keys()
            #resultSensitiveParamsDict[key] = sorted(resultSensitiveParamsDict[key],key=resultSensitiveParamsDict[key].index)
        #print resultSensitiveParamsDict
        return resultSensitiveParamsDict



    def write2file(self):
        sensitiveParamsList = getSensitiveParamsFromFile()
        newSensitiveParamsList = []
        #print self.resultSensitiveParamsDict
        for rspdKey in self.resultSensitiveParamsDict.keys():
            if (self.resultSensitiveParamsDict[rspdKey] != []) and (set(self.resultSensitiveParamsDict[rspdKey]).issubset(set(sensitiveParamsList)) == False):
                    newSensitiveParamsList.extend([newSensitiveParam for newSensitiveParam in self.resultSensitiveParamsDict[rspdKey] if newSensitiveParam not in sensitiveParamsList])
        #print str(newSensitiveParamsList)

        if newSensitiveParamsList != []:
            newSensitiveParamsList = {}.fromkeys(newSensitiveParamsList).keys()

            with open('sensitive-params.txt','a') as sps:
                for nsp in newSensitiveParamsList:
                    #print 'writeNewParams:'+nsp
                    sps.write('\n'+nsp)







    def addAndSaveNewParamRegular(self, event):
        NewParamRegular = self.addAndSaveNewParamRegularTextField.getText()
        if NewParamRegular not in self.sensitiveParamR:
            self.sensitiveParamR.append(NewParamRegular)
            with open(paramRegularFile,'a') as prf:
                prf.write('\n'+NewParamRegular)
            self.alertSaveSuccess.showMessageDialog(self.spePanel, "Add and save success!")
        else:
            self.alertSaveSuccess.showMessageDialog(self.tab, "paramRegular existed.")

        self.sensitiveParamsRegularListPanel.setListData(self.sensitiveParamR)
        self.sensitiveParamsRegularListPanel.revalidate()

        #self.sensitiveParamR = getParamRegular()



    def delParamRegular(self,event):
        #delParamRegularsIndex = self.sensitiveParamsRegularListPanel.selectedIndex
        #if delParamRegularsIndex >= 0:
        #    print delParamRegularsIndex
        #    print self.sensitiveParamR[delParamRegularsIndex]
        for sprlp in self.sensitiveParamsRegularListPanel.getSelectedValuesList():
            #print sprlp
            self.sensitiveParamR.remove(sprlp)

        #with open(paramRegularFile,'r') as prf1:
        #    lines = prf1.readlines()

        with open(paramRegularFile,'w') as prf2:
            #print self.sensitiveParamsRegularListPanel.getSelectedValuesList()
            #for line in lines:
            #    if line.strip() in self.sensitiveParamsRegularListPanel.getSelectedValuesList():
            #        print 'remove:'+line
            #        lines.remove(line)
            #for spr1 in lines:
            #    #print spr1
            #    prf2.write(spr1)
            for spr2i, spr2 in enumerate(self.sensitiveParamR):
                print spr2i
                print spr2
                if spr2i == len(self.sensitiveParamR)-1:
                    prf2.write(spr2)
                else:
                    prf2.write(spr2+'\n')

        self.sensitiveParamsRegularListPanel.setListData(self.sensitiveParamR)
        self.sensitiveParamsRegularListPanel.revalidate()

        #self.sensitiveParamR = getParamRegular()

       

    

    def clearRst(self, event):
          self.outputTxtArea.setText("")

    def exportRst(self, event):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.logPane, "Choose file")
        filename = chooseFile.getSelectedFile().getCanonicalPath()
        print "\n" + "Export to : " + filename
        open(filename, 'w', 0).write(self.outputTxtArea.text)




    def getUiComponent(self):
        self.spePanel = JPanel()
        self.spePanel.setBorder(None)
        self.spePanel.setLayout(None)
        
        self.logPane = JScrollPane()
        self.outputTxtArea = JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self.outputTxtArea.setLineWrap(True)
        self.logPane.setViewportView(self.outputTxtArea)
        self.spePanel.add(self.logPane)

        self.clearBtn = JButton("Clear", actionPerformed=self.clearRst)
        self.exportBtn = JButton("Export", actionPerformed=self.exportRst)
        self.parentFrm = JFileChooser()

        self.spePanel.add(self.clearBtn)
        self.spePanel.add(self.exportBtn)

        self.logPane.setBounds(20,50,800,600)
        
        self.clearBtn.setBounds(20,650,100,30)
        self.exportBtn.setBounds(600,650,100,30)

        self.sensitiveParamsRegularListPanel = JList(self.sensitiveParamR)
        self.sensitiveParamsRegularListPanel.setVisibleRowCount(len(self.sensitiveParamR))

        #self.spePanel.add(self.sensitiveParamsRegularListPanel)

        #self.sensitiveParamsRegularListPanel.setBounds(850,50,150,600)

        self.sensitiveParamsRegularListScrollPanel = JScrollPane()
        self.sensitiveParamsRegularListScrollPanel.setViewportView(self.sensitiveParamsRegularListPanel)
        self.spePanel.add(self.sensitiveParamsRegularListScrollPanel)
        self.sensitiveParamsRegularListScrollPanel.setBounds(850,50,150,600)

        self.addAndSaveNewParamRegularButton = JButton('add&&save',actionPerformed=self.addAndSaveNewParamRegular)
        self.spePanel.add(self.addAndSaveNewParamRegularButton)
        self.addAndSaveNewParamRegularButton.setBounds(1000,50,150,30)

        self.addAndSaveNewParamRegularTextField = JTextField('NewParamRegular')
        self.spePanel.add(self.addAndSaveNewParamRegularTextField)
        self.addAndSaveNewParamRegularTextField.setBounds(1150,50,100,30)

        self.alertSaveSuccess = JOptionPane()
        self.spePanel.add(self.alertSaveSuccess)

        self.delParamRegularButton = JButton("delete",actionPerformed=self.delParamRegular)
        self.spePanel.add(self.delParamRegularButton)
        self.delParamRegularButton.setBounds(1000,90,100,30)

        return self.spePanel