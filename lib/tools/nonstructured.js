/////////////////////////////////////////////////////////
//                                                     //
// "nonstructured.js"                                  //
// A Framework for Non-Structure Oriented Programming  //
// Implementation                                      //
// Copyright(c) 2008 Atsushi Oka [ http://oka.nu/ ]    //
// This script file is distributed under the LGPL      //
//                                                     //
/////////////////////////////////////////////////////////

// Please check nonstructured.examples.js. 
// There are many examples with description to learn how to use nonstructured.js.

var NonStructureLib = require('./NonStructureLib');
var ElapsedTime = require('./elapse');
var label = NonStructureLib.label;
var Paramn = NonStructureLib.Paramn;
var StackFramen = NonStructureLib.StackFramen;
var ResultWrappern = NonStructureLib.ResultWrappern;


var nonstructured = module.exports = (function () {

var nonstructure = {};

/*
var packageRoot = this;
if ( packageRoot.__PACKAGE_ENABLED ) {
  __unit( "nonstructured.js" );
}
*/


Nonstructured.log = function(message) {
  // trace(message);
  return;
};
Nonstructured.err = function(message) {
  trace(message);
  return;
};
var log = function(message){
  Nonstructured.log(message);
  return;
}
var err = function(message){
  Nonstructured.err(message);
  return;
};

/**
 * A constructor of Nonstructured class. The constructor has variable
 * length parameters. You can pass any Function objects any Array
 * objects at this parameter. They will be stored in an internal queue
 * described below. Though you usually do not have to call this
 * constructor directly. Use ready() method instead.
 *
 * Once it starts, the closure will be repeatedly called until it returns
 * false.  When the closure returns another closure, it will be queued
 * on an internal stack as a statement and the closure will be processed
 * recursively. 
 */
function Nonstructured(/*...args */) {
  this._stack = [];
  this._scope = NonStructureLib.proc.getNew(); // {}
  this._frequency = Nonstructured.frequency;
  this._timeout  = 1;
  //this._done = function(){};
  //this._progress = function(){};
  this._done = NonStructureLib.proc.getNew(function(){});
  this._done.IS_RUNNABLE = function () { return true; };
  this._progress = NonStructureLib.proc.getNew(function(){});
  this._progress.IS_RUNNABLE = function () { return true; };

  this._limit = createLimitChecker(-1);
  if ( 0<arguments.length ) {
    var a = [];
    for ( var i=0;i<arguments.length;i++ ) {
      a[i] = arguments[i];
    }
    this.initialize( a );
  }
};

Nonstructured.frequency = 1;

function createLimitChecker(value) {
  if ( value < 0 )  {
    return function(stepCount) {
      return false;
    };
  } else {
    return function(stepCount) {
      return value<stepCount;
    };
  }
}

function initialize( closures ) {
  var param = Paramn.getNew();
  var subparam = Paramn.getNew();

  for ( var i=0; i<closures.length; i++ ) {
    this._stack[i] = StackFramen.getNew( closures[i], subparam, param );
    param=subparam;
    subparam= Paramn.getNew();
  }

  return this;
}

Nonstructured.prototype.initialize = initialize;

var callClosureNormal = function( id, closure, scope, param, subparam ) {
  if (closure.valFun) {
    return closure.valFun( scope, param, subparam );
  }
  if (typeof closure != 'function') {
    throw 'not a cunction';
  }
  return closure( scope, param, subparam );
};
var callClosureTrace = function( id, closure, scope, param, subparam ) {
  var name = ( closure.__NAME == null ) 
	? 'CLOSURE=' + (id==null?"unknown":id) 
      : 'CLOSURE=' + closure.__NAME + "/"+ (id==null?"unknown":id);
  var et = ElapsedTime.create();
  et.start( name );
  var result = closure( scope, param, subparam );
  et.stop();
  return result;
};

var callClosure = callClosureNormal;
Nonstructured.traceResponce = function( v ) {
  if ( v ) {
    callClosure = callClosureTrace;
  } else {
    callClosure = callClosureNormal;
  }
};

/**
 * Process the top statement on the stack.
 *
 * In non-structured programming, a procedure can be divided into small
 * pieces of code chunk which are represented as a closure. In another
 * point of view, A closure is a statement. I prefer use this term.  A
 * statement is supposed to be called repeatedly until it returns false.
 * And I call this each calling "step".This process() method processes a
 * step. 
 *
 * You can fully execute the procedure in this way :
 *
 *     var i=0;
 *     var f=function() {
 *         return i++<10;
 *     };
 *     
 *     var nonstructured = f.ready();
 *     while ( nonstructured.process() ) {
 *         trace("processing!");
 *     }
 *     trace("done!");
 */

Nonstructured.prototype.process = function() {
  if ( this._stack.length == 0 ) 
    return false;

  var result;
  var current = this._stack[0];
  var closure = current.closure;
  var scope = this._scope;

  closure = closuring( closure );

  result = callClosure( "others", closure, scope, current.param, current.subparam );


  if ( result === undefined ) {
    err( "*** WARNING MAY BE MISSING return STATEMENT *** " );
  }


  result = result || label.CONTINUE;
  //result = nonstructure.augmentObj(result);

  if ( ! result.IS_CONTINUE() ) {
    this._stack.shift();
  }

  if ( result.IS_RESULT_WRAPPER() ) {
    result = result.unwrap();
  }

  if ( result.IS_RUNNABLE() && ! result.IS_FLOW_CONTROLLER() ) {
    // queueing a new stack frame.
    this._stack.unshift( StackFramen.getNew( result, current.subparam, Paramn.getNew()));//new Param() ) );
  }

  return 0<this._stack.length;
};

Nonstructured.prototype.step = Nonstructured.prototype.process; 

/**
 * Methods below are setter/getter methods. Get a current value without
 * parameter and set a value with specific parameter.
 */

/**
 * limit() 
 *
 * limit property specifies the maximum steps for the execution.
 * If the count of steps exceeds this limit property, it will
 * automatically stop and notify the error.
 */
Nonstructured.prototype.limit = function( value ) {
  if ( arguments.length == 0 ) {
    return this._limit;
  } else {
    this._limit = createLimitChecker( value );
    return this;
  }
};

/**
 * frequency()
 *
 * This frequency property specifies the frequency of step execution.
 * Nonstructured.go() method internally uses JavaScript's standard
 * global method setInterval()/clearInterval(). This frequency property
 * is applied to it.
 */
Nonstructured.prototype.frequency = function( value ) {
  if ( arguments.length == 0 ) {
    return this._frequency;
  } else {
    this._frequency = value;
    return this;
  }
};

/**
 * timeout()
 *
 * This timeout property specifies the maximum elapsed time of each
 * timer calling.  Each timer calling, Nonstructured tries to call as
 * many steps until certain amount of time elapsed. This timeout
 * property specifies the amount of time in milliseconds.
 */
Nonstructured.prototype.timeout = function( value ) {
  if ( arguments.length == 0 ) {
    return this._timeout;
  } else {
    this._timeout = value;
    return this;
  }
};

/**
 * done() 
 *
 * done property specifies a procedure to be done when this object
 * finished to process all statements.
 */
Nonstructured.prototype.done = function( value ) {
  if ( arguments.length == 0 ) {
    return this._done;
  } else {
    this._done = value;
    return this;
  }
};

/**
 * progress() 
 *
 * progress property specifies a procedure to be call back when a
 * statement is processed.
 */
Nonstructured.prototype.progress = function( value ) {
  if ( arguments.length == 0 ) {
    return this._progress;
  } else {
    this._progress = value;
    return this;
  }
};


/**
 * go()
 *
 * go() method automatically calls all statements in the internal stack.
 * If frequency property is zero or less than zero, Nonstructured tries
 * to call all statements and it will never return until the last
 * statement returns false.
 *
 * If frequency property is larger than zero, Nonstructured try to
 * execute it asynchronously. 
 */
Nonstructured.prototype.go = function() {
  log( "go()" );
  if ( this._frequency <=0 ) {
    return executeSync( this, this._limit, this._done, this._progress );
  } else {
    return executeAsync( this, this._frequency, this._timeout, this._limit, this._done, this._progress ); 
  }
}


/**
 * private methods.
 */

function closuring( o ) {

  if ( o.IS_RESULT_WRAPPER !=null && o.IS_RESULT_WRAPPER() ) {
    o = o.unwrap();
  }

  if ( o.__installedClosure == null ) {
    if (o.isValArr) {
      o.__installedClosure = list( o );
    } else {
      o.__installedClosure = o;
    }
  }

  return o.__installedClosure;
}


function zerof( n, digit ) {
  n = ""+n;
  while ( n.length < digit ) {
    n="0"+n;
  }
  return n;
}

/**
 * list()
 *
 * Creates a multiple-statement.  This method returns a newly generated
 * closure which executes multiple closures. 
 */

function list( closures ) {
  if (!closures) throw 'closures no defined';

  log( "Nonstructured.list start : the number of closures:" + closures.length );
  // for ( var i=0; i<closures.length; i++ ) {
  // 	log( "list["+i+"]="+closures[i] );
  // }
  
  var et = ElapsedTime.create();
  var first=true;

  var enterProc = function(){
    first=false;
    et.start( 'CLOSURE='+closureName + "(total)" );
  };
  var exitProc = function(){
    et.stop();
    first=true;
    reset();
  };

  var closureName = closures.__NAME;
  var labelName = closures.__LABEL_NAME;

  var i =0;
  function reset() { i =0; }
  function next() { i++; }

  var result = function( scope, param, subparam ) {
    if ( first ) enterProc();

    if (closures.valArr) {
      var closure = closuring( closures.valArr[ i ] );
    } else {
      throw '[!!!] closure not found';
    }
    
    var name = closure.__NAME == null ? closureName + "("+ zerof(i,2) +")" : closure.__NAME;
    var result = callClosure( name , closure, scope, param, subparam );

    log( "list() closure() result: " + result );

    if ( result === undefined ) {
      err( "*** WARNING MISSING return STATEMENT ***" );
    }

    result = result || label.CONTINUE;

    // NOTE1: If the result value is a Label object and their
    //        IDENTIFIED() values are not identical, ignore and
    //        deligate it to lower lebel lists/closures.
    // NOTE2: LABEL object is inherently same as EXIT operation.
    // NOTE3: Propagate this LABEL object to upper stack frames so do not replace the result.
    if ( result.IS_FLOW_CONTROLLER() ) {
      if ( ( ! result.IS_LABEL() ) || ( result.LABELED() == closures.IDENTIFIED() ) ) {
	if ( result.IS_CONTINUE() ) {
	  // reset();
	  result = label.CONTINUE;
	} else if ( result.IS_BREAK() ) {
	  next();
	  result = label.CONTINUE;
	} else if ( result.IS_AGAIN() ) {
	  reset();
	  result = label.CONTINUE;
	} else if ( result.IS_EXIT() ) {
	  exitProc();
	  result = label.BREAK;
	} else {
	  // THIS CAN'T BE HAPPENED
	  err("*** warning list() warning *** ");
	  next();
	  result = label.CONTINUE;
	}
      } else {
	// trace("L2");
	// REFER TO NOTES ABOVE.
	exitProc();
	// result = BREAK;
      }

      if ( closures.valArr.length <= i  ) {
	err( "WARNING(1) *** MULTI-STATEMENT OVERED ITS LAST STATEMENT *** MAYBE MISSING FLOW-CONTROLLER *** " );
	exitProc();
	result = label.BREAK;
      }

    } else {
      // Wrap the result value by ResultWrapper object. 
      // The result value is not always fresh new instance druing it loops. 
      // modification for result causes skipping necessary procedure.
      // to avoid this issue, wrapping it before any modification is required. 

      if ( ( ! result.IS_LABEL() ) || ( result.LABELED() == closures.IDENTIFIED() ) ) {
	if ( result.IS_CONTINUE() ) {
	  // reset();
          result = ResultWrappern.getNew(result).CONTINUE();
	} else if ( result.IS_BREAK() ) {
	  next();
          result = ResultWrappern.getNew(result).CONTINUE();
	} else if ( result.IS_AGAIN() ) {
	  reset();
          result = ResultWrappern.getNew(result).CONTINUE();
	} else if ( result.IS_EXIT() ) {
	  exitProc();
          result = ResultWrappern.getNew(result).BREAK();

	} else {
	  // DEFAULT BEHAVIOR ( SAME AS BREAK )
	  next();
	  result = ResultWrappern.getNew( result ).CONTINUE();
	}
      } else {
	// trace("L1/" + result.LABELED() + "/"+closures.IDENTIFIED() );
	// REFER TO NOTES ABOVE.
	exitProc();
	// result = new ResultWrapper( result ).BREAK();
      }
      //if ( closures.length <= i  ) {
      if ( closures.valArr.length <= i  ) {
	err( "WARNING(2) *** MULTI-STATEMENT OVERED ITS LAST STATEMENT *** MAYBE MISSING FLOW-CONTROLLER *** " )
	exitProc();
	result = ResultWrappern.getNew( result ).BREAK();
      }
    }
    return result;
  };

  if (labelName) result.__LABEL_NAME = labelName;
  if (closureName) result.__NAME = closureName;
  return result;
};

/**
 * executeSync()
 * Execute all statements synchronously.
 */
function executeSync( nonstructured, limit, done, progress ) {
  log("Nonstructured.executeSync:start >> ");
  var count=0;
  var startTime = new Date();
  for(;;){
    count++;
    if ( ! nonstructured.process() ) {
      log("Nonstructured.executeSync:done <<" );
      var finishTime = new Date();
      done( true, count, ( finishTime.getTime() -startTime.getTime() ), startTime, finishTime );
      break;
    }
    progress( count );
    if ( limit( count ) ) {
      log("Nonstructured.executeSync:done ( exceed count limit ) <<" );
      var finishTime = new Date();
      done( false, count, ( finishTime.getTime() -startTime.getTime() ), startTime, finishTime );
      break;
    }
  }
  return null;
};

/**
 * executeAsync()
 * Execute all statements asynchronously.
 */

function executeAsync( nonstructured, frequency, timeout, limit, done, progress ) {
  log("Nonstructured.executeAsync:start >>" );
  var startTime = new Date();
  var finishTime;
  var synchronizedFlg = false;
  var count =0;
  var f = function() {
    if ( synchronizedFlg ) {
      log( "confliction was detected." );
      return;
    } else {
      synchronizedFlg=true;
      var s = new Date().getTime();
      for ( var i=0;;i++ ){
	count++;
	if ( ! nonstructured.process() ) {
	  log("Nonstructured.executeAsync:done <<");
	  clearInterval( id );

	  finishTime = new Date();
	  done( true, count, ( finishTime.getTime()-startTime.getTime() ), startTime, finishTime );
	  break;
	}
	progress( count );
	if ( limit(count) ) {
	  log("Nonstructured.executeAsync:done (exceed count limit)  <<");
	  clearInterval( id );

	  finishTime = new Date();
	  done( false, count, ( finishTime.getTime()-startTime.getTime() ), startTime, finishTime );
	  break;
	}
	var e = new Date().getTime();
	if ( timeout < e-s  ) {
	  log("Async:count"+i);
	  break;
	}
      }
      synchronizedFlg=false;
    }
  };
  var id = setInterval( f, frequency );
  return id;
};


  label.CONTINUE.CONTINUE();
  label.BREAK.BREAK();
  label.AGAIN.AGAIN();
  label.EXIT.EXIT();
  label.LABEL.LABEL().EXIT();

/////////////////////////////////////////////////////////////////////////
// NOTE : Using LABEL function itself as a constant flow controller is
// available but not recommended.  It will work as EXIT with default
// label name.

//packageRoot.Nonstructured = Nonstructured;
  
  return Nonstructured;

}());