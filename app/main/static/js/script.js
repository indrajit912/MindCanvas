function goBack() {
    // Function to go back
    window.history.back();
}

// The following gives the color to the tags
$(document).ready(function () {
  $('.badge').each(function () {
    var color = $(this).data('color');
    $(this).css('background-color', color);
  });
});