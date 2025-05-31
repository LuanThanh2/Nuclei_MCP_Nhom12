$(document).ready(function () {
  // Lọc theo mức độ nghiêm trọng
  $("#severityFilter").change(function () {
    const severity = $(this).val();
    const rows = $(".result-row");
    if (rows.length === 0) return; // Tránh lỗi nếu không có hàng
    rows.each(function () {
      if (severity === "all" || $(this).data("severity") === severity) {
        $(this).show();
      } else {
        $(this).hide();
      }
    });
  });

  // Tìm kiếm
  $("#searchInput").on("input", function () {
    const searchText = $(this).val().toLowerCase();
    const rows = $(".result-row");
    if (rows.length === 0) return; // Tránh lỗi nếu không có hàng
    rows.each(function () {
      const endpoint = $(this).find("td:eq(0)").text().toLowerCase();
      const payload = $(this).find("td:eq(1)").text().toLowerCase();
      if (endpoint.includes(searchText) || payload.includes(searchText)) {
        $(this).show();
      } else {
        $(this).hide();
      }
    });
  });
});
