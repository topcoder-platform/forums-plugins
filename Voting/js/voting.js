jQuery(document).ready(function($) {

  // Handle Vote button clicks
  $(document).on('click', '.Voter a', function() {

      var btn = this;
      var parent = $(this).parents('.Voter');
      var votes = $(parent).find('span.CountVoices');
      var voteUp = $(parent).find('.SpriteUp');
      var voteDown = $(parent).find('.SpriteDown');
      $.ajax({
        type: "POST",
        url: btn.href,
        data: 'DeliveryType=BOOL&DeliveryMethod=JSON',
        dataType: 'json',
        error: function(XMLHttpRequest, textStatus, errorThrown) {
          gdn.informError(xhr);
        },
        success: function(json) {
          // Change the Vote count
          $(votes).text(json.TotalScore);
          $(voteUp).removeClass('Voted');
          $(voteDown).removeClass('Voted');
          $(voteUp).addClass(json.VoteUpCssClass);
          $(voteDown).addClass(json.VoteDownCssClass);
          gdn.inform(json);
        }
      });
      return false;
  });

});

// Updates The Total Of Comments After A Comment Has Been Added
$(document).on('CommentAdded', function() {
  $('.VotingSort strong').html($('.MessageList li.ItemComment').length+' Comment'+($('.MessageList li.ItemComment').length > 1 ? 's' : ''));
});

// Updates The Total Of Comments After A Comment Has Been Deleted
$(document).on('CommentDeleted', function() {
  $('.VotingSort strong').html($('.MessageList li.ItemComment').length+' Comment'+($('.MessageList li.ItemComment').length > 1 ? 's' : ''));
});