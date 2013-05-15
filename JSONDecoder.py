# Burp Extension - JSON decoder
# Copyright : Michal Melewski <michal.melewski@gmail.com>

# Small content-type fix: Nicolas Gregoire

import json

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
  def registerExtenderCallbacks(self, callbacks):
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()

    callbacks.setExtensionName('JSON Decoder')
    callbacks.registerMessageEditorTabFactory(self)
    
    return
  
  def createNewInstance(self, controller, editable): 
    return JSONDecoderTab(self, controller, editable)
    
class JSONDecoderTab(IMessageEditorTab):
  def __init__(self, extender, controller, editable):
    self._extender = extender
    self._helpers = extender._helpers
    self._editable = editable
    
    self._txtInput = extender._callbacks.createTextEditor()
    self._txtInput.setEditable(editable)
    
    return
    
  def getTabCaption(self):
    return "JSON Decoder"
    
  def getUiComponent(self):
    return self._txtInput.getComponent()
    
  def isEnabled(self, content, isRequest):  
    if isRequest:
      r = self._helpers.analyzeRequest(content)
    else:
      r = self._helpers.analyzeResponse(content)
      
    for header in r.getHeaders():
      if header.lower().startswith("content-type:"):
        content_type = header.split(":")[1].lower()
        if content_type.find("application/json") > 0 or content_type.find("text/javascript") > 0:
          return True
        else:
          return False

    return False
    
  def setMessage(self, content, isRequest):
    if content is None:
      self._txtInput.setText(None)
      self._txtInput.setEditable(False)
    else:
      if isRequest:
        r = self._helpers.analyzeRequest(content)
      else:
        r = self._helpers.analyzeResponse(content)
      
      msg = content[r.getBodyOffset():].tostring()

      print msg

      garbage = msg[:msg.find("{")] + "\n"
      clean = msg[msg.find("{"):]

      try:
        pretty_msg = garbage + json.dumps(json.loads(clean), indent=4)
      except:
        print "problem parsing data in setMessage"
        pretty_msg = garbage + clean

      self._txtInput.setText(pretty_msg)
      self._txtInput.setEditable(self._editable)
      
    self._currentMessage = content
    return
    
  def getMessage(self): 
    if self._txtInput.isTextModified():
      try:
        pre_data = self._txtInput.getText()
        garbage = pre_data[:pre_data.find("{")]
        clean = pre_data[pre_data.find("{"):]
        data = garbage + json.dumps(json.loads(clean))
      except:
        data = self._helpers.bytesToString(self._txtInput.getText())
        
      # Reconstruct request/response
      r = self._helpers.analyzeRequest(self._currentMessage)
        
      return self._helpers.buildHttpMessage(r.getHeaders(), self._helpers.stringToBytes(data))
    else:
      return self._currentMessage
    
  def isModified(self):
    return self._txtInput.isTextModified()
    
  def getSelectedData(self):
    return self._txtInput.getSelectedText()
