function updateStatusCol(hash, repoUrl) {
    $.get('/api/status/' + hash, function (data) {
        var matches = '';
        var first = true;

        if (typeof data.job.status === 'undefined') {
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

        data.matches.forEach(function (m) {
            $('#matches').find('tbody')
                .append($('<tr />')
                    .append($('<td />')
                        .append($('<a />')
                            .attr('href', '/sample?name=' + m.matched_dump)
                            .text(m.matched_dump.split('.').slice(0, -1).join('.')))
                        .append($('<a />')
                            .attr('href', repoUrl.replace('{hash}', m.binary_hash))
                            .attr('class', 'label label-info pull-right')
                            .text('analysis')
                        )))
        });

        $('#progressBar').css('width', progress + '%');
        $('#progressBar').text(progress + '%');
        $('#matchesNum').text(data.matches.length);
        $('#jobStatus').text(data.job.status);
        $('#jobStatus').removeClass('label-danger label-success label-info');

        if (data.job.status == 'failed') {
            $('#jobStatus').addClass('label-danger');
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

        $('#matches').removeClass('hidden');
        $('#queryPlan').addClass('hidden');

        if (data.job.status != 'done') {
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
