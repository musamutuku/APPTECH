// logout script
function logOut(){
    document.getElementById('homeDiv').style.opacity ="0.2";
    document.getElementById('homeDiv').style.pointerEvents ='none';
    document.getElementById('homeDiv').style.opacity ="0.2";
    document.getElementById('logout-box').style.display = "block";
}
function closeLog(){
    document.getElementById('logout-box').style.display = "none";
    document.getElementById('homeDiv').style.opacity ="1";
    document.getElementById('homeDiv').style.pointerEvents = 'all';
}
function clickOk(){
    document.getElementById('click-okbtn').click();
}


// register page script
function logForm(){
    var x = document.getElementById("usernm").value;
    var y = document.getElementById("paswd").value;
    var z = document.getElementById("conf-paswd").value;
    var w = document.getElementById("input-error");

    if (x != "" && y != "" && z != "") {
        if(y == z && y.length >= 6){
            var logform = document.getElementById("login-det");
            var accform = document.getElementById("account-det");
            var next_btn = document.getElementById("next-btn");
            var back_btn = document.getElementById("back-btn");
            logform.style.visibility = "hidden";
            accform.style.visibility = "visible";
            next_btn.style.visibility = "hidden";
            back_btn.style.visibility = "visible";
            w.style.visibility = "hidden";
        }
        else if(y.length < 6){
            document.getElementById("input-error").innerHTML= "Minimum length of password required is 6 characters!";
             w.style.visibility = "visible";
             document.getElementById("input-error").style.display = "block";
        }
        else{
            document.getElementById("input-error").innerHTML= "Password does not match!";
             w.style.visibility = "visible";
             document.getElementById("input-error").style.display = "block";
        }
    }
    else{
        document.getElementById("input-error").innerHTML= "Please fill all the fields!";
        w.style.visibility = "visible";
        document.getElementById("input-error").style.display = "block";
    }
}
function accForm(){
    var logform = document.getElementById("login-det");
    var accform = document.getElementById("account-det");
    var next_btn = document.getElementById("next-btn");
    var back_btn = document.getElementById("back-btn");
    logform.style.visibility = "visible";
    accform.style.visibility = "hidden";
    next_btn.style.visibility = "visible";
    back_btn.style.visibility = "hidden";
}
function validateForm() {
    var pin = document.forms["myForm"]["pin"].value;
    var conf_pin = document.forms["myForm"]["confirm_pin"].value;
    if(pin.length >= 4){
        if (pin != conf_pin) {
            document.getElementById("pin-error").innerHTML= "PIN does not match!";
            document.getElementById("pin-error").style.display = "block";
            return false;
        }
    } 
    else{
        document.getElementById("pin-error").innerHTML= "Minimum length of PIN required is 4 characters!";
        document.getElementById("pin-error").style.display = "block";
        return false;
    }
}
function checkValue(){
    var user_check = document.getElementById("usernm").value;
    const ul_nav1 = document.getElementById('nav2');
    const listItems = ul_nav1.getElementsByTagName('li');

    for (var i = 0; i <= listItems.length - 1; i++) {
        if (user_check == listItems[i].innerHTML){
            document.getElementById("check1").innerHTML = "Username is already taken. Try another!";
            document.getElementById("check1").style.display = "block";
            }
        }
        
    }
function checkId(){
    var id_check = document.getElementById("id-No").value;
    const ul_nav2 = document.getElementById('nav1');
    const listItemz = ul_nav2.getElementsByTagName('li');

    for (var i = 0; i <= listItemz.length - 1; i++) {
        if (id_check == listItemz[i].innerHTML){
            document.getElementById("check2").innerHTML = "That ID number already exists!";
            document.getElementById("check2").style.display = "block";
            }
        }
        
    }
function waitValue(){
    document.getElementById("check1").style.display = "none";
    document.getElementById("input-error").style.display = "none";
}
function waitId(){
    document.getElementById("check2").style.display = "none";
}
function waitConfirm(){
    document.getElementById("input-error").style.display = "none";
}
function waitPin(){
    document.getElementById("pin-error").style.display = "none";
}
function lowCaseFn(){
    var fname = document.getElementById("fName");
    fname.value = fname.value.charAt(0).toUpperCase() + fname.value.slice(1);
}
function lowCaseLn(){
    var lname = document.getElementById("lName");
    lname.value = lname.value.charAt(0).toUpperCase() + lname.value.slice(1);
}


// account page script
function showBtns(){
    var thebtns = document.getElementById('theBtns');
    var statediv = document.getElementById('stateDiv');
    var transbtn = document.getElementById('transactionbtn');
    var statebtn = document.getElementById('statebtn')
    thebtns.style.visibility = "visible";
    statediv.style.visibility = "hidden";
    transbtn.style.background = "#FFFFFF";
    statebtn.style.background = "#C4C4C4";
}
function showStatediv(){
    var thebtns = document.getElementById('theBtns');
    var statediv = document.getElementById('stateDiv');
    var transbtn = document.getElementById('transactionbtn');
    var statebtn = document.getElementById('statebtn')
    statediv.style.visibility = "visible";
    thebtns.style.visibility = "hidden";
    statebtn.style.background = "#FFFFFF";
    transbtn.style.background = "#C4C4C4";
}
function hideShow1(){
    var form1 = document.getElementById("checkbal-form");
    var form2 = document.getElementById("depositcash-form");
    var form3 = document.getElementById("withdrawcash-form");
    var forms = document.getElementById("formpage");
    var homepg = document.getElementById("homepage");
    form1.style.display = "block";
    form2.style.display = "none";
    form3.style.display = "none";
    forms.style.display = "block";
    homepg.style.display = "none";
}
function hideShow2(){
    var form1 = document.getElementById("checkbal-form");
    var form2 = document.getElementById("depositcash-form");
    var form3 = document.getElementById("withdrawcash-form");
    var forms = document.getElementById("formpage");
    var homepg = document.getElementById("homepage");
    form1.style.display = "none";
    form2.style.display = "block";
    form3.style.display = "none";
    forms.style.display = "block";
    homepg.style.display = "none";
}
function hideShow3(){
    var form1 = document.getElementById("checkbal-form");
    var form2 = document.getElementById("depositcash-form");
    var form3 = document.getElementById("withdrawcash-form");
    var forms = document.getElementById("formpage");
    var homepg = document.getElementById("homepage");
    form1.style.display = "none";
    form2.style.display = "none";
    form3.style.display = "block";
    forms.style.display = "block";
    homepg.style.display = "none";
}
function showHome1(){
    var forms = document.getElementById("formpage");
    var homepg = document.getElementById("homepage");
    document.getElementById("form1").reset();
    forms.style.display = "none";
    homepg.style.display = "block";
}
function showHome2(){
    var forms = document.getElementById("formpage");
    var homepg = document.getElementById("homepage");
    document.getElementById("form2").reset();
    forms.style.display = "none";
    homepg.style.display = "block";
}
function showHome3(){
    var forms = document.getElementById("formpage");
    var homepg = document.getElementById("homepage");
    document.getElementById("form3").reset();
    forms.style.display = "none";
    homepg.style.display = "block";
}
function showDepo(){
    document.getElementById("depobtn").click();
}
function showStatement(){
    document.getElementById('content').style.display = "none";
    document.getElementById('stateDiv').style.display = "block";
    document.getElementById('transactionbtn').style.background = "#C4C4C4";
    document.getElementById('transactionlink').style.pointerEvents = "all";
    document.getElementById('statebtn').style.background = "#FFFFFF";
    document.getElementById('backto-div').style.display = "none";
}

// user_details page script
function editName(){
    document.getElementById('edit-uname').disabled = false;
    document.getElementById('edit-fname').disabled = false;
    document.getElementById('edit-lname').disabled = false;
    document.getElementById('edit-phone').disabled = false;
    document.getElementById('edit-id').style.background = "#cee6ee";
    document.getElementById('savebtn').style.display = "block";
    document.getElementById('editbtn').style.display = "none";
}
function lowCaseFn(){
    var fname = document.getElementById("edit-fname");
    fname.value = fname.value.charAt(0).toUpperCase() + fname.value.slice(1);
}
function lowCaseLn(){
    var lname = document.getElementById("edit-lname");
    lname.value = lname.value.charAt(0).toUpperCase() + lname.value.slice(1);
}
function hideErrorMsg(){
    document.getElementById('reset-error').style.display = "none";
}

// show notification and profile icon
function showIcon(){
    document.getElementById('notify-name').style.display = "block";
    document.getElementById('pic-icon').style.display = "none";
    document.getElementById('notify-icon').style.display = "none";
    document.getElementById('notify-div').style.display = "none";

}
function showNotify(){
    document.getElementById('notify-div').style.display = "block";
    document.getElementById('notify-icon').style.display = "none";
    document.getElementById('pic-icon').style.display = "none";
    document.getElementById('notify-name').style.display = "none";
}
function closeNotify(){
    document.getElementById('notify-div').style.display = "none";
    document.getElementById('notify-icon').style.display = "block"
    document.getElementById('pic-icon').style.display = "block";
    document.getElementById('notify-name').style.display = "none";
}
function closeNotify2(){
    document.getElementById('notify-div').style.display = "none";
    document.getElementById('notify-icon').style.display = "block"
    document.getElementById('pic-icon').style.display = "block";
    document.getElementById('notify-name').style.display = "none";
    document.getElementById('notifybtn').click();
}
function closeName(){
    document.getElementById('notify-name').style.display = "none";
    document.getElementById('pic-icon').style.display = "block";
    document.getElementById('notify-icon').style.display = "block";
    document.getElementById('notify-div').style.display = "none";
}

//systeminfo
function clickBack(){
    document.getElementById('clicklink').click();
}

// search user
function searchUser(){
    var input, filter, table, tr, td, i;
    input = document.getElementById("search-input");
    filter = input.value.toUpperCase();
    table = document.getElementById("t-two");
    tr = table.getElementsByTagName("tr");


    // Loop through all table rows, and hide those who don't match the search query
    for (i = 0; i < tr.length; i++) {
    
        td = tr[i].getElementsByTagName("td") ; 
        for(j=0 ; j<td.length ; j++)
        {
          let tdata = td[j] ;
            if (tdata) {
                if (tdata.innerHTML.toUpperCase().indexOf(filter)>-1) {
                    tr[i].style.display = "";
                    break;
                 }
                else {
                    tr[i].style.display = "none";
                }
            }  
          } 
        } 
     }

function hideSearchError(){
    document.getElementById('trshow').innerHTML = "";
}

// manage users
function manageUser(){
    var table = document.getElementById("t-two");
    for (var i = 0; i < table.rows.length; i++) {
        var firstCol = table.rows[i].cells[0];
        btn = firstCol.childNodes[0];
        btn.addEventListener("click", function(event){
            var input = document.getElementById("manage-input");
            input.value = event.target.innerHTML;
            var input = document.getElementById("managebtn").click();
        });      
    }
}

function deactivateAccount(){
    var userid = document.getElementById('span-id').innerHTML;
    var user_input = document.getElementById('input-id').innerHTML;
    user_input.value = userid;
    document.getElementById('deactivatebtn').click();
}