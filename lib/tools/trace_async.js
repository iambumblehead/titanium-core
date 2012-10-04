/*
 * trace.async.js
 * Simple debugging tool.
 * See trace.async.readme.txt for further information.
 *
 * Copyright(c) 2009 Atsushi Oka [ http://oka.nu/ ]
 * This script file is distributed under the LGPL
 */
function initTraceAsync(packageRoot) {
    if ( packageRoot.__PACKAGE_ENABLED ) {
	__unit( "trace.js" );
    }

    var proc = function() {
	if ( queueModified && traceWindow != null && ( ! traceWindow.closed ) ) {
	    queueModified=false;
	    createHTML();
	}
    };
    var timer = setInterval( proc, 500 );
    var queue = [];
    var queueModified = false;

    function createWindow(){
	traceWindow = window.open( "","trace", "left=0,top=0,width=500,height=300,scrollbars=yes,location=no,status=no,menubar=no" );
    }

    function createHTML(){
	var d = traceWindow.document ;
	d.open( "text/html", false );
	d.writeln( "<html>" );
	d.writeln( "<head>" );
	d.writeln( "<title>" );
	d.writeln( "Trace Window" );
	d.writeln( "</title>" );
	d.writeln( "</head>" );
	d.writeln( "<body>" );
	for ( var i=0; i<queue.length; i++ ) {
	    d.writeln( queue[i]+ "<br>" );
	}
	// var checked = "";
	// d.writeln( "<form name='form1'>" );
	// d.writeln( "<input type='checkbox' name='check1' value='check1'"+checked+">" );
	// d.writeln( "lock" );
	// d.writeln( "</form>" );
	d.writeln( "</body>" );
	d.writeln( "</html>" );
	d.close();

	traceWindow.scrollTo( 0, 2147483647 );
    }

    var traceWindow=null;
    function reactivate() {
	if ( traceWindow==null || traceWindow.closed ) {
	    createWindow();
	}
    }

    function post( s ) {
	queue.push( s );
	queueModified = true;
    }

    function trace( s ) {
	reactivate();
	post(s);
    }
    packageRoot.trace = trace;
}
initTraceAsync(this);
// vim:ts=8:

