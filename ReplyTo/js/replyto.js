jQuery(document).ready(function($) {
   
   function param(href, name) {
      return (href.split(name + '=')[1] || '').split('&')[0];
   }

   //If view is not flat, reload a page to rebuild a tree
   function reloadPage() {
      var currentView = param(window.location.href, 'view');
      return  (currentView == 'tree' || currentView == 'threaded');
   }

   $(document).on('click','a.ReplyComment', function(ev) {
      var btn = this;
      var parent = $(btn).parents('.MainContent');
      var commentContainer = $(parent).find('div.CommentForm');
      var header = $(commentContainer).find('h2.H');
      // Form
      var form = $(commentContainer).find('form#Form_Comment');
      var href = $(btn).attr('href');
      var commentID = param(href,'ParentCommentID');
      var hiddenField = $(form).find(':input[type="hidden"]#Form_ParentCommentID')

      var author = '';
      if(commentID == '') { // No Parent Comment, Reply to Discussion
         commentID = 0;
         author = $(btn).parents('.Discussion').find('.Item-Header.DiscussionHeader .Author .topcoderHandle').text();
      } else {
         author = $(btn).parents('.Comment').find('.Item-Header.CommentHeader .Author .topcoderHandle').text();
      }

      $(header).text('Replying to '+ author);

      if($(hiddenField).length == 0) {
         var el = '<input type="hidden" name="ParentCommentID" id="Form_ParentCommentID" value="' + commentID + '"></input>';
         $(form).append(el);
      } else {
         $(hiddenField).val(commentID);
      }
      var formButtons = $(form).find('.Buttons');
      var postCommentButton = $(form).find('.CommentButton');
      postCommentButton.val('Post Reply');
      var backButton = $(formButtons).find('.Button.PreviewButton');
      var cancelReplyButton = $(formButtons).find('span.Reply');
      if($(cancelReplyButton).length == 0) {
         var cancelReplyButton = '<span class="Reply"><a href="/" class="Button CancelReplyComment">Cancel Reply</a></span>';
         $(cancelReplyButton).insertBefore(backButton);
      } else {
         $(cancelReplyButton).show();
      }
      $(form)[0].scrollIntoView();
      return false;
   });

   $(document).on('clearCommentForm',function(ev) {
      var doc =  this;
      var formElement= $(doc).find('div.CommentForm');
      clearReplyCommentForm($(formElement));
      return false;
   });


   // Comment was added.
   $(document).on('CommentAdded',function(ev) {
      if (reloadPage() === true) {
         window.location.reload();
         return false;
      }
      return false;
   });

   // Comment was deleted.
   $(document).on('CommentDeleted',function(ev) {
      if (reloadPage() === true) {
         window.location.reload();
         return false;
      }
      return false;
   });

   $(document).on('click','a.CancelReplyComment', function(ev) {
      clearReplyCommentForm(this);
      return false;
   });

   function clearReplyCommentForm(formElementSender) {
      var parent = $(formElementSender).parents('.MainContent');
      var commentContainer = $(parent).find('div.CommentForm');
      var header = $(commentContainer).find('h2.H');
      $(header).text('Leave a comment');
      var form = $(commentContainer).find('form#Form_Comment');
      var hiddenField = $(form).find(':input[type="hidden"]#Form_ParentCommentID')
      if($(hiddenField).length > 0) {
         $(hiddenField).val(0);
      }
      var formButtons = $(form).find('.Buttons');
      var postCommentButton = $(form).find('.CommentButton');
      postCommentButton.val('Post Comment');
      var cancelReplyButton = $(formButtons).find('span.Reply');
      if($(cancelReplyButton).length > 0) {
         $(cancelReplyButton).hide();
      }
   }
});