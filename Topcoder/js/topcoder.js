jQuery(document).ready(function($) {

  // Set up paging
  if ($.morepager) {

    $('#WatchingDiscussionsMore').morepager({
      pageContainerSelector: 'ul.Discussions:last',
      afterPageLoaded: function() {
        $(document).trigger('DiscussionPagingComplete');
      }
    });

    // profile/discussions paging
    $('#WatchingCategoriesMore').morepager({
      pageContainerSelector: 'ul.WatchedCategoryList:last',
      afterPageLoaded: function() {
        $(document).trigger('DiscussionPagingComplete');
      }
    });
  }
});
