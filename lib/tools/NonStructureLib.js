var cornClone = (function () {
  function F(){}
  return function(parent) {
    F.prototype = parent;
    return new F;
  };
}());

////////////////////////////////////////////////////////
// non struct
////////////////////////////////////////////////////////
var nonstruct  = (function () {
  var protoObj = {
    isAugmented : true,
    valArr : [],
    valFun : null,

    ///////////////////////////////////
    ready : function () {
      return new Nonstructured( this );
    },

    NAME : function ( name ) {
      if ( arguments.length == 0 ) {
	return this.__NAME;
      } else {
	this.__NAME = name;
	return this;
      }
    },
    IDENTIFY : function( name ) {
      this.__LABEL_NAME = name || 'DEFAULT_LABEL';
      return this;
    },
    IDENTIFIED : function() {
	return this.__LABEL_NAME;
    },
    
    ////////////////////////////////////////
    ////////////////////////////////////////
    AGAIN : function () {
      this.__AGAIN = true;
      return this;
    },
    EXIT : function () {
      this.__EXIT = true;
      return this;
    },
    CONTINUE : function () {
      this.__CONTINUE = true;
      return this;
    },
    BREAK : function () {
      this.__BREAK = true;
      return this;
    },
    LABEL : function (name) {
      this.__LABEL = name || 'DEFAULT_LABEL';
      return this;
    },

    ////////////////////////////////////////
    ////////////////////////////////////////
    // flow control check functions
    IS_AGAIN : function () { 
      return (this.__AGAIN != null) ? true : false;
    },
    IS_EXIT : function () { 
      return (this.__EXIT != null) ? true : false;
    },
    IS_CONTINUE : function () {
      return (this.__CONTINUE != null) ? true : false;
    },
    IS_BREAK : function () {
      return (this.__BREAK != null) ? true : false;
    },
    IS_LABEL : function () {
      return (this.__LABEL != null) ? true : false;
    },

    ////////////////////////////////////////
    ////////////////////////////////////////
    RESET_AGAIN : function () {
      delete this.__AGAIN;
      return this;
    },
    RESET_EXIT : function () {
      delete this.__EXIT;
      return this;
    },
    RESET_CONTINUE : function () {
      delete this.__CONTINUE;
      return this;
    },
    RESET_BREAK : function () {
      delete this.__BREAK;
      return this;
    },
    RESET_LABEL : function () {
      delete this.__LABEL;
      return this;
    },

    LABELED : function (name) {
      return this.__LABEL;
    },

    IS_RUNNABLE : function () { return (this.valFun || typeof this == 'function') ? true : false; },
    IS_RESULT_WRAPPER : function () { return false; },
    IS_FLOW_CONTROLLER : function () { return false; }
  };

  return {
    addFlow : function (o) {},

    getProto : function () {
      var that =  cornClone(protoObj);
      return that;
    },

    augmentProto : function (func) {
      func.prototype = nonstruct.getAugmented(func.prototype);
      return func;
    },

    getNew : function (valArr) {
      var that = cornClone(protoObj);
      that.isAugmented = true;
      that.valArr = valArr || [];
      if (valArr) that.isValArr = true;
      if (valArr) that.IS_RUNNABLE = function () { return true; };
      return that;
    },
    // careful should only be used by BigInteger and RSA
    getAugmented : function (obj) {
      for (var o in protoObj) {
        if (protoObj.hasOwnProperty(o)) {
          obj[o] = protoObj[o];
        }
      }
      if (typeof obj == 'function') {
         obj.IS_RUNNABLE = function () { return true; };
      }
      return obj;
    },

    getFlowController : function (name) {
      var that = cornClone(protoObj);
      that.isAugmented = true;
      that.valArr = [];
      that.IS_FLOW_CONTROLLER  = function () { return true; };
      that.valFun = function () {
        return that;
      };
      if (name) {
        that.toString = function () {
	  return "FlowController."+name+"";
        };
      }
      return that;
    },
    

    getFlowController2 : function (name) {
      var that = this.getAugmented(function (labelName) {
        var g =  cornClone(protoObj);
        g.LABEL(labelName);
        return g;
      });
      that.IS_FLOW_CONTROLLER  = function () { return true; };
      if (name) {
        that.toString = function () {
	  return "FlowController."+name+"(null)";          
        };
      }
      return that;
    }
  };

}());


////////////////////////////////////////////////////////
// result wrapper
////////////////////////////////////////////////////////
var ResultWrappern = (function (wrapper) {
  wrapper = nonstruct.getNew();
  wrapper.IS_RESULT_WRAPPER = function () { return true; },
  wrapper.result = '';
  wrapper.toString = function () { 
    return "class ResultWrapper() : " + this.result; 
  };
  wrapper.unwrap = function () {
    if (this.result.IS_RESULT_WRAPPER()) {
      return this.result.unwrap();
    } else {
      return this.result;
    }
  };

  return {
    getNew : function ( result ) {
      var that = cornClone(wrapper);
      that.result = result;
      return that;
    }
  };
}());

////////////////////////////////////////////////////////
// result param
////////////////////////////////////////////////////////
var Paramn = (function (param) {
  param = nonstruct.getNew();
  param.toString = function () {
    var names =[];

    if ('result' in this) {
      if (!('result' in param)) names.push('result');
    }

    names.sort();

    var s ="";
    for ( var i=0; i<names.length; i++ ) {
      s=s+names[i]+"="+this[names[i]] +"\n";
    }
    return "class Param(\n" + s + ")";
  };


  return {
    getNew : function () {
      var that = cornClone(param);
      return that;
    }
  };
}());


////////////////////////////////////////////////////////
// stack
////////////////////////////////////////////////////////
var StackFramen = (function (stackframe) {
  stackframe = nonstruct.getNew();

  return {
    getNew : function (closure, param, subparam) {
      var that = cornClone(param);
      that.closure = closure;
      that.param= param;
      that.subparam= subparam;
      return that;
    }
  };    
}());

////////////////////////////////////////////////////////
// glob
////////////////////////////////////////////////////////
var labels = 2;

var glob = {
  CONTINUE : nonstruct.getFlowController('CONTINUE'), 
  BREAK : nonstruct.getFlowController('BREAK'),
  AGAIN : nonstruct.getFlowController('AGAIN'),
  EXIT : nonstruct.getFlowController('EXIT'),
  LABEL : nonstruct.getFlowController2('LABEL')
};
