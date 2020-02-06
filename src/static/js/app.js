function updateStatusCol(hash, repoUrl) {
    $.get('/api/status/' + hash, function (data) {
        var matches = '';
        var first = true;

        if (typeof data.job.status === 'undefined') {
            return;
        }

        if (data.job.status == 'parsed') {
            $('#jobStatus').text('parsed');
            return;
        }

        var total_volume = data.job.total_files;

        if (data.job.max_files != -1 && data.job.max_files < data.job.total_files) {
            total_volume = data.job.max_files;
        }

        var progress = Math.round(data.job.files_processed * 100 / total_volume);

        if (total_volume == 0) {
            progress = 100;
        }

        $('#matches').find('tbody').empty();

        var count_meta = 0;

        data.matches.forEach(function (m) {
            var new_td = $('<td />');
            var m_add = $('#matches').find('tbody').append($('<tr />').append(new_td));

            new_td.append($('<a />')
                            .attr('href', '/sample?name=' + m.file)
                            .text(m.file.split('.').slice(0, -1).join('.')));

            if (!m.meta) {
                return;
            }

            count_meta += 1;

            Object.keys(m.meta).forEach(function (meta_key) {
                var obj = m.meta[meta_key];

                if (obj.display_text) {
                    new_td.append($('<a />')
                        .attr('href', obj.url)
                        .attr('class', 'label label-info pull-right')
                        .text(obj.display_text)
                    );
                }
            });
        });

        $('#progressBar').css('width', progress + '%');
        $('#progressBar').text(progress + '%');
        $('#matchesNum').text(data.matches.length);
        $('#jobStatus').text(data.job.status);
        $('#jobStatus').removeClass('label-danger label-success label-info');

        if (data.job.status == 'failed') {
            $('#jobStatus').addClass('label-danger');

            $('#runtime-errors').text(data.error);
            $('#runtime-errors').removeClass('hidden');
            $('#matches').addClass('hidden');
            $('#queryPlan').addClass('hidden');
        } else if (data.job.status == 'done') {
            $('#jobStatus').addClass('label-success');
        } else {
            $('#jobStatus').addClass('label-info');
        }

        if (typeof data.job.files_processed !== 'undefined') {
            $('#processed').text(data.job.files_processed + '/' + total_volume);
        } else {
            $('#processed').text('-');
        }

        $('#progressBar').removeClass('progress-bar-info progress-bar-success');

        if (data.job.status == 'done') {
            $('#progressBar').addClass('progress-bar-success');
        } else {
            $('#progressBar').addClass('progress-bar-info');
        }

        if (data.job.status != 'failed') {
            $('#matches').removeClass('hidden');
            $('#queryPlan').addClass('hidden');
        }

        if (data.job.status != 'done' || count_meta < data.matches.length) {
            setTimeout(updateStatusCol, 1000, hash, repoUrl);
        }
    });
}

$(function() {
    var jobInfo = $('#jobInfo');
    var hash = jobInfo.data('hash');
    var repoUrl = jobInfo.data('repo-url');

    if (hash) {
        updateStatusCol(hash, repoUrl);
    }

    $('.action-save-as').on('click', function () {
        $('#saveAsModal').modal();
    });
});
