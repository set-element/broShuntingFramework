broShuntingFramework
====================

The shunting framework uses a series of state transitions to define the behavior.  The various tranition states are:

  CutoffTime - Connections are analyzed for an observation period.  When that period expires 
      without adequate data being moved, then the session object is set to 'CutoffTime' and 
      the state removed.
  
  FlowTrackInit
  
  FlowTrackRemove
  
  RemoveConnection
  
  ShuntClear
  
  ShuntFlowInit
  
  ShuntTrackerIncrement
  
  ShuntTrigger
  
  


