# Burp Extension - Argonaut
# Copyright : Michal Melewski <michal.melewski@gmail.com>

# Process all request parameters
# and try to find if they are echoed back in response

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter

# Java imports
from javax.swing import JTable
from javax.swing import JScrollPane
from javax.swing.table import AbstractTableModel

# Python imports
import re

# Consts
MIN_PARAM_LEN = 3
SNIPPET_SIZE = 80


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
  def registerExtenderCallbacks(self, callbacks):
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()

    callbacks.setExtensionName('Argonaut')
    callbacks.registerMessageEditorTabFactory(self)
    
    return
  
  def createNewInstance(self, controller, editable): 
    return ArgonautTab(self, controller, editable)

    
class ArgonautTab(IMessageEditorTab):
  def __init__(self, extender, controller, editable):
    self._extender = extender
    self._controller = controller
    self._helpers = extender._helpers
    
    # Data container
    self._dataContainer = ArgonautData()

    self._argoTable = ArgonautTable(self._dataContainer)
    self._tablePane = JScrollPane(self._argoTable)
    
    return
    
  def getTabCaption(self):
    return "Argonaut"
    
  def getUiComponent(self):
    return self._tablePane
    
  def isEnabled(self, content, isRequest):
    """Enable if parameters were present. Including cookies"""
    if isRequest:
      return False
    else:
      req = self._helpers.analyzeRequest(self._controller.getRequest())

    params =  req.getParameters()

    if params.isEmpty():
      return False

    return True
  
  def setMessage(self, content, isRequest):
    if isRequest:
      return

    # Extract params from pair
    req = self._helpers.analyzeRequest(self._controller.getRequest())
    params =  req.getParameters()

    # Grab response
    rsp = self._helpers.analyzeResponse(content)
    body = content[rsp.getBodyOffset():].tostring()

    # Parse
    self._dataContainer.reset()
    self.argoParse(self._dataContainer, params, body)
    self._dataContainer.fireTableDataChanged()

    return
    
  def isModified(self):
    return False


  def argoParse(self, container, params, body):
    for param in params:
      paramValue = param.getValue()

      # Param testing
      if len(paramValue) < MIN_PARAM_LEN: continue

      # Search body (TODO: add transformations)
      indexes = [(a.start(), a.end()) for a in list(re.finditer(paramValue, body))]
      
      # Extract
      if indexes:
        for start, end in indexes:
          # TODO: more intelligent snippet
          snippet = body[max(0,start-30):min(end+30, len(body))]

          
          container.insertRow(paramValue, 'plain', snippet)

# Stylying
class ArgonautTable(JTable):
  def __init__(self, dataModel):
    self.setModel(dataModel)
    return

class ArgonautData(AbstractTableModel):
  _data = []
  
  def reset(self):
    self._data = []

  def insertRow(self, paramValue, transformation, snippet):
    entry = {
              'paramValue': paramValue,
              'transformation': transformation,
              'snippet': snippet
            }

    self._data.append(entry)

  def getRowCount(self):
    print 'row count'
    print self._data
    return len(self._data)

  def getColumnCount(self):
    return 3

  def getColumnName(self, columnIndex):
    if columnIndex == 0:
      return "Parameter Value"
    if columnIndex == 1:
      return "Transformation"
    if columnIndex == 2:
      return "Snippet"
    
    return ""

  def getValueAt(self, rowIndex, columnIndex):
    dataEntry = self._data[rowIndex]

    if columnIndex == 0:
      return dataEntry['paramValue']
    if columnIndex == 1:
      return dataEntry['transformation']
    if columnIndex == 2:
      return dataEntry['snippet']
  
    return ""