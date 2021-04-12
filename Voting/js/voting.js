jQuery(document).ready(function($) {

  // Handle Vote button clicks
  $(document).on('click', '.Voter a', function() {

      var btn = this;
      var parent = $(this).parents('.Voter');
      var votes = $(parent).find('span.CountVoices');
      $.ajax({
        type: "POST",
        url: btn.href,
        data: 'DeliveryType=VIEW&DeliveryMethod=JSON',
        dataType: 'json',
        error: function(xhr, textStatus, errorThrown) {
          gdn.informError(xhr);
        },
        success: function(json) {
          gdn.processTargets(json.Targets);
        }
      });
      return false;
  });

});
