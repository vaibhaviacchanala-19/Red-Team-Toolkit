const sessionReports = [];

function addSessionReport(report) {
  const existingIndex = sessionReports.findIndex(item => item._id === report._id);
  if (existingIndex !== -1) {
    sessionReports.splice(existingIndex, 1);
  }

  sessionReports.unshift(report);
  if (sessionReports.length > 20) {
    sessionReports.pop();
  }

  return report;
}

function getSessionHistory() {
  return sessionReports;
}

function getSessionReport(id) {
  return sessionReports.find(report => report._id === id);
}

function deleteSessionReport(id) {
  const index = sessionReports.findIndex(report => report._id === id);
  if (index !== -1) {
    sessionReports.splice(index, 1);
    return true;
  }
  return false;
}

module.exports = {
  addSessionReport,
  getSessionHistory,
  getSessionReport,
  deleteSessionReport
};
