# Extension 6, ver 2 - JSON decoder

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter

from java.io import PrintWriter
import json

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		
		callbacks.setExtensionName('Example 6, version 2 - JSON Decoder')
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
		
		# Help printers
		self._stdout = PrintWriter(extender._callbacks.getStdout(), True)
		
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
			if header.startswith("Content-Type:"): 
				if header.split(":")[1].find("application/json") > 0: return True
			
		return False
		
	def setMessage(self, content, isRequest):
		# Strip garbage and get only {*} (to avoid json garbage in front)
		# Form it nicely and display via setText

		if isRequest:
			r = self._helpers.analyzeRequest(content)
		else:
			r = self._helpers.analyzeResponse(content)
		
		msg = content[r.getBodyOffset():].tostring()
		
		pretty_msg = json.dumps(json.loads(msg), sort_keys=True, indent=4)
		
		self._txtInput.setText(pretty_msg)
		self._txtInput.setEditable(self._editable)
		
		# Do something with it
		self._currentMessage = content
		return
		
	def getMessage(self, content, isRequest):
		# get the content
		# strip not needed characters and repack
		return self._currentMessage
		
	def isModified(self):
		return self._txtInput.isTextModified()
		
	def getSelectedData(self):
		return self._txtInput.getSelectedText()