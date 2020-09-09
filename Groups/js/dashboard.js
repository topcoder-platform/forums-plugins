/*!
 * Dashboard v3 - A new dashboard design for Vanilla.
 *
 * @author    Becky Van Bussel <beckyvanbussel@gmail.com>
 * @copyright 2016 (c) Becky Van Bussel
 * @license   MIT
 */

'use strict';

(function($) {

    /**
     * Adapted from http://stackoverflow.com/questions/4459379/preview-an-image-before-it-is-uploaded
     * Sets a image preview url for a uploaded files, not yet saved to the the server.
     * There's a rendering function for this in Gdn_Form: `imageUploadPreview()`.
     * You'll probably want to use it to generate the markup for this.
     *
     * Selectors: `.js-image-preview`
     *            `.js-image-preview-new`
     *            `.js-image-preview-form-group`
     */
    function readUrl(input) {
        if (input.files && input.files[0]) {
            var $preview = $(input).parents('.js-image-preview-form-group').find('.js-image-preview-new .js-image-preview');
            var reader = new FileReader();
            reader.onload = function (e) {
                if (e.target.result.startsWith('data:image')) {
                    $preview.attr('src', e.target.result);
                }
            };
            reader.readAsDataURL(input.files[0]);
        }
    }

    // Event handlers

    /**
     * Adds a preview of the uploaded, not-yet-saved image.
     * There's a rendering function for this in Gdn_Form: `imageUploadPreview()`.
     * You'll probably want to use it to generate the markup for this.
     *
     * Selectors: `.js-image-upload`
     *            `.js-image-preview-old`
     *            `.js-image-preview-new`
     *            `.js-image-preview-form-group`
     */
    $(document).on('change', '.js-image-upload', function() {
        $(this).parents('.js-image-preview-form-group').find('.js-image-preview-new').removeClass('hidden');
        $(this).parents('.js-image-preview-form-group').find('.js-image-preview-old').addClass('hidden');
        readUrl(this);
    });

    /**
     * Removes the preview image and clears the file name from the input.
     * There's a rendering function for this in Gdn_Form: `imageUploadPreview()`.
     * You'll probably want to use it to generate the markup for this.
     *
     * Selectors: `.js-remove-image-preview`
     *            `.js-image-preview-old`
     *            `.js-image-preview-new`
     *            `.js-image-preview`
     *            `.js-image-upload`
     *            `.js-image-preview-form-group`
     */
    $(document).on('click', '.js-remove-image-preview', function(e) {
        e.preventDefault();
        var $parent = $(this).parents('.js-image-preview-form-group');
        $parent.find('.js-image-preview-old').removeClass('hidden');
        $parent.find('.js-image-preview-new').addClass('hidden').find('.js-image-preview').attr('src', '');
        var $input = $parent.find('.js-image-upload');
        var $inputFileName = $parent.find('.file-upload-choose');
        $input.val('');
        $input.removeAttr('value');
        $inputFileName.html($inputFileName.data('placeholder'));
    });

    /**
     * File Upload filename preview.
     * There's a rendering function for this in Gdn_Form: `fileUpload()`.
     * You'll probably want to use it to generate the markup for this.
     *
     * Selector: `.js-file-upload`
     */
    $(document).on('change', '.js-file-upload', function() {
        var filename = $(this).val();
        if (filename.substring(3, 11) === 'fakepath') {
            filename = filename.substring(12);
        }
        if (filename) {
            $(this).parent().find('.file-upload-choose').html(filename);
        }
    });

})(jQuery);

