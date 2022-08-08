function remove_ans(){
  //alert("remove ans clicked");
  var id = $(this).attr('id');
  //alert(id);
  var split_id = id.split("remove_");
  //alert(split_id);
  var deleteindex = split_id[1];
  //alert(deleteindex);
  var all_div_after = $("#div_" + deleteindex).nextAll();
  // Remove div with id
  $("#div_" + deleteindex).remove();
  all_div_after.each(function(){
    //alert($(this).attr('id'));
    var chs=$(this).children();
    chs.each(function(){
      var id2alter =($(this).attr('id'));
      var last_underscore=-1;
      for (let ii = 0; ii < id2alter.length; ii++) {
        if (id2alter[ii] == '_') {
          last_underscore=ii;
        }
      }
      //alert(Number(id2alter.slice(last_underscore+1))-1);
      //alert(id2alter.slice(0,last_underscore+1));
      $(this).attr('id', id2alter.slice(0,last_underscore+1)+(Number(id2alter.slice(last_underscore+1))-1));
    })
    var divid2alter =($(this).attr('id'));
    var last_underscore_div=-1;
    for (let ii = 0; ii < divid2alter.length; ii++) {
      if (divid2alter[ii] == '_') {
        last_underscore_div=ii;
      }
    }
    $(this).attr('id', divid2alter.slice(0,last_underscore_div+1)+(Number(divid2alter.slice(last_underscore_div+1))-1));
  });
}
// Add new element (a choice of ans)
function add_ans(){
  //alert("add is clicked")
  var id = $(this).attr('id');
  var row_idx_clicked = id.split("_")[1];
  //alert(row_idx_clicked);
  var lastid = $(`.element_${row_idx_clicked}:last`).attr("id");
  var last_elemnt_cnt = lastid.split("_");
  var nextindex = Number(last_elemnt_cnt[2]) + 1;
  //alert(nextindex);
  //alert(`.element_${row_idx_clicked}:last`);
  // Adding new div container after last occurance of element class
  $(`.element_${row_idx_clicked}:last`).after(`<div class='element_${row_idx_clicked}' id='div_${row_idx_clicked}_${nextindex}'></div>`);

  // Adding element to <div>
  $(`#div_${row_idx_clicked}_${nextindex}`).append(`<input type='text' name = 'R_${row_idx_clicked}' placeholder='answer' id='text_${row_idx_clicked}_${nextindex}'>&nbsp;<span id='remove_${row_idx_clicked}_${nextindex}' class='remove_ans'>Delete</span>`);
    // Remove element
  $(".remove_ans").off('click').on('click',remove_ans); //attach callback to remove ans
}

function row_html(rowIdx){
  html_string = `<tr name = 'containerz' id="R${rowIdx}">
        <td class="row-index text-center">
          <div class='form-group'>
    
      
            <div class="container" >

              <label for="question">Question </label>
              <input type="text" id="ques_${rowIdx}" name = 'R_${rowIdx}'><br>
              Answer(s) <input type="text" id="anws_${rowIdx}" name = 'A_${rowIdx}' placeholder='; to separate multi-choice by ;'>
              <div class='element_${rowIdx}' id='div_${rowIdx}_0'>
                <span class='add' id='add_${rowIdx}'>Add</span>
              </div> <!-- element -->

            </div> <!-- container -->


          </div> <!-- form-group -->
        <td class="text-center">
          <button class="btn btn-danger remove_row"
          type="button">Remove</button>
        </td>
        
      </tr>`;
  return html_string;
}

function remove_row() {

  // Getting all the rows next to the row
  // containing the clicked button
  var child = $(this).closest('tr').nextAll();

  // Iterating across all the rows
  // obtained to change the index
  /* fix it later
  child.each(function () {
    // Getting <tr> id.
    var id = $(this).attr('id');

    // Getting the <p> inside the .row-index class.
    var idx = $(this).children('.row-index').children('p');

    // Gets the row number from <tr> id.
    var dig = parseInt(id.substring(1));

    // Modifying row index.
    idx.html(`Row ${dig - 1}`);

    // Modifying row id.
    $(this).attr('id', `R${dig - 1}`);
  });
  */

  // Removing the current row.
  $(this).closest('tr').remove();

  // Decreasing total number of rows by 1.
}
function add_row() {
  let rowIdx = 0;
  let lastRowIdx = 0;
  if ($("#tbody tr").length > 0){
    lastRowIdx = Number($("#tbody tr").last().attr('id').split('R')[1]);
  }
  rowIdx = lastRowIdx + 1;
  //console.log('last tr',$("#tbody tr:last"));
  //console.log('last row id', lastRowIdx);
  //console.log('tr length',$("#tbody tr").length);
  //console.log($("#tbody tr:last").attr('id'));
  // Adding a row inside the tbody.
  $('#tbody').append(row_html(rowIdx));
  // attach CB to "Add new element(a choice of ans)"
  $(".add").off('click').on('click',add_ans);//.add click
  // attach CB to "Remove a row".
  $('.remove_row').off('click').on('click', remove_row); 
}