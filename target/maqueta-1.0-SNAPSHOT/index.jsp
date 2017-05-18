<%-- 
    Document   : index
    Created on : 26/04/2017, 04:42:10 PM
    Author     : francisco.perdomo
--%>

<%@page contentType="text/html" pageEncoding="windows-1252"%>
<!DOCTYPE html>
<html>
    <head>
        <style>
        .button 
        {
            display: inline-block;
            padding: 15px 25px;
            font-size: 24px;
            cursor: pointer;
            text-align: center;
            text-decoration: none;
            outline: none;
            color: #fff;
            background-color: #323cd0;
            border: none;
            border-radius: 15px;
            box-shadow: 0 9px #999;
          }

        .button:hover {background-color: #212996}

        .button:active 
        {
            background-color: #212996;
            box-shadow: 0 5px #666;
            transform: translateY(4px);
        }
        </style>
    </head>
    <script type="text/javascript">
        function startTime()
        {
            var today=new Date();
            var h=today.getHours();
            var m=today.getMinutes();
            var s=today.getSeconds();
            // add a zero in front of numbers<10
            m=checkTime(m);
            s=checkTime(s);
            document.getElementById('txt').innerHTML=h+":"+m+":"+s;
            //t=setTimeout('startTime()',500);
        }
        function checkTime(i)
            {
                if (i<10){i="0" + i;}
            return i;
            }
</script>
</head>
<body onload="startTime()">
<div id="txt"></div>
        <h2> Maqueta OpenSAML 3.2 </h2>

        <a href="SSO_FULL" class="button"> SSO </button> </br>

    </body>
</html>
