"use strict";

module.exports.public = async (event) => {
  console.log("Requesting public route...", new Date().toISOString());

  return {
    statusCode: 200,
    body: JSON.stringify(event, null, 2),
  };
};

module.exports.private = async (event) => {
  console.log("Requesting private route...", new Date().toISOString());

  return {
    statusCode: 200,
    body: JSON.stringify(event, null, 2),
  };
};
